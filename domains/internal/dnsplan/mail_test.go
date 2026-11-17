package dnsplan

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/miekg/dns"

	"github.com/portcullis/domains/internal/fakedns"
)

const (
	mh     = "mail." + pd // MAIL_HOSTNAME
	spki   = "8d02536c887482bc34ff54e41d2ba659bf85b341a0a20afadb5813dcfbcf286d"
	dkimRS = "v1-rsa-20261115._domainkey." + pd
	dkimED = "v1-ed25519-20261115._domainkey." + pd
)

// rsaTXT is a 410-byte DKIM TXT (an RSA-2048 key's size): longer than one
// 255-byte character-string.
func rsaTXT() string {
	b := make([]byte, 294)
	for i := range b {
		b[i] = byte(i*7 + 3)
	}
	s := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(b)
	if len(s) != 410 {
		panic(fmt.Sprintf("rsaTXT is %d bytes", len(s)))
	}
	return s
}

// mainMail is the main domain's mail set (contract §19.7) with the HELO
// SPF and the TLSA at MAIL_HOSTNAME.
func mainMail() []MailRecord {
	return []MailRecord{
		{Name: pd, Type: "MX", TTL: 3600, Value: "10 " + mh + "."},
		{Name: pd, Type: "TXT", TTL: 3600, Value: "v=spf1 mx -all"},
		{Name: mh, Type: "TXT", TTL: 3600, Value: "v=spf1 a -all"},
		{Name: dkimRS, Type: "TXT", TTL: 3600, Value: rsaTXT()},
		{Name: dkimED, Type: "TXT", TTL: 3600, Value: "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="},
		{Name: "_dmarc." + pd, Type: "TXT", TTL: 3600, Value: "v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:dmarc-reports@" + pd},
		{Name: "_smtp._tls." + pd, Type: "TXT", TTL: 3600, Value: "v=TLSRPTv1; rua=mailto:tls-reports@" + pd},
		{Name: "_submissions._tcp." + pd, Type: "SRV", TTL: 3600, Value: "0 1 465 " + mh + "."},
		{Name: "_imaps._tcp." + pd, Type: "SRV", TTL: 3600, Value: "0 1 993 " + mh + "."},
		{Name: "_submission._tcp." + pd, Type: "SRV", TTL: 3600, Value: "0 1 587 " + mh + "."},
		{Name: "_imap._tcp." + pd, Type: "SRV", TTL: 3600, Value: "0 0 0 ."},
		{Name: "_pop3._tcp." + pd, Type: "SRV", TTL: 3600, Value: "0 0 0 ."},
		{Name: "_pop3s._tcp." + pd, Type: "SRV", TTL: 3600, Value: "0 0 0 ."},
		{Name: "_25._tcp." + mh, Type: "TLSA", TTL: 3600, Value: "3 1 1 " + spki},
	}
}

// mailEnv: the plan env with two resolvers (both judge) and a provider
// that splits long TXT like Porkbun (split) or stores them whole like
// Cloudflare; ops counts the provider's writes.
func mailEnv(t *testing.T, split bool) (*env, *opCount) {
	t.Helper()
	e := newPlanEnv(t)
	e.in.Resolvers = append(serveZone(t, e.zone), serveZone(t, e.zone)...)
	ops := &opCount{n: map[string]int{}}
	e.in.Provider = &fakedns.Provider{Zone: e.zone, ZoneName: pz, TXTSplit255: split, Hook: ops.hook}
	e.in.Spec.Main = true
	e.in.Spec.MailHost = mh
	e.in.Spec.Mail = mainMail()
	return e, ops
}

type opCount struct {
	mu sync.Mutex
	n  map[string]int
}

func (o *opCount) hook(op string, _ []libdns.Record) error {
	o.mu.Lock()
	o.n[op]++
	o.mu.Unlock()
	return nil
}

func (o *opCount) writes() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.n["append"] + o.n["delete"] + o.n["set"]
}

func mailItemsOf(p Plan) []Item { return items(p, SetMail) }

func assertMailOK(t *testing.T, p Plan) {
	t.Helper()
	its := mailItemsOf(p)
	if len(its) == 0 {
		t.Fatalf("no mail items in %+v", p.Items)
	}
	for _, it := range its {
		if it.Status != StatusOK || it.Severity != SevOK {
			t.Errorf("mail item %s %s = %s (want %v live %v steps %v)", it.Name, it.Type, it.Status, it.Want, it.Live, it.Steps)
		}
	}
}

func TestWantedMailSetReplacesNoMail(t *testing.T) {
	w := Wanted(Spec{Name: pd, NoMail: true, Main: true, Mail: mainMail()})
	if _, ok := w[SetNoMail]; ok {
		t.Fatalf("nomail wanted next to mail: %v", w[SetNoMail])
	}
	if len(w[SetMail]) != len(mainMail()) {
		t.Fatalf("mail wanted %d records, want %d", len(w[SetMail]), len(mainMail()))
	}
	// Without mail, nomail is back.
	if w := Wanted(Spec{Name: pd, NoMail: true}); len(w[SetNoMail]) != 3 || len(w[SetMail]) != 0 {
		t.Fatalf("nomail only: %v", w)
	}
	// The plan has no nomail item either.
	e, _ := mailEnv(t, false)
	e.in.Spec.NoMail = true
	if its := items(Build(context.Background(), e.in), SetNoMail); len(its) != 0 {
		t.Fatalf("nomail items next to mail: %+v", its)
	}
}

// TestMailSetLongTXTRoundTrip (Review Focus 2): a 410-byte DKIM TXT is
// written, served as ≤ 255-byte strings, read back by both resolvers as
// their concatenation and judged ok; a second apply writes nothing.
func TestMailSetLongTXTRoundTrip(t *testing.T) {
	for _, split := range []bool{true, false} {
		t.Run(fmt.Sprintf("split=%v", split), func(t *testing.T) {
			e, ops := mailEnv(t, split)
			ctx := context.Background()
			if _, _, err := Apply(ctx, e.in, []string{SetMail}); err != nil {
				t.Fatal(err)
			}
			stored := e.zone.Records(dkimRS)
			if len(stored) != 1 {
				t.Fatalf("stored %v", stored)
			}
			if split != strings.HasPrefix(stored[0].Data, `"`) {
				t.Fatalf("stored as %q", stored[0].Data)
			}
			// On the wire: several strings, each ≤ 255 bytes, joined = the value.
			for _, r := range e.in.Resolvers {
				m := new(dns.Msg)
				m.SetQuestion(dkimRS+".", dns.TypeTXT)
				in, _, err := (&dns.Client{Net: "tcp"}).Exchange(m, r)
				if err != nil || len(in.Answer) != 1 {
					t.Fatalf("query at %s: %v %v", r, in, err)
				}
				txt := in.Answer[0].(*dns.TXT).Txt
				if len(txt) < 2 || strings.Join(txt, "") != rsaTXT() {
					t.Fatalf("served %d strings %q", len(txt), txt)
				}
				for _, s := range txt {
					if len(s) > 255 {
						t.Fatalf("a %d-byte character-string", len(s))
					}
				}
			}
			assertMailOK(t, Build(ctx, e.in))
			before := ops.writes()
			if _, _, err := Apply(ctx, e.in, []string{SetMail}); err != nil {
				t.Fatal(err)
			}
			if n := ops.writes() - before; n != 0 {
				t.Fatalf("a second apply wrote %d times: %v", n, e.zone.Records(dkimRS))
			}
			if got := e.zone.Records(dkimRS); len(got) != 1 {
				t.Fatalf("after the second apply %v", got)
			}
		})
	}
}

// TestMailItemsSPFKeepsOtherTXT: the SPF at <e> replaces only the SPF
// string; a site verification stays.
func TestMailItemsSPFKeepsOtherTXT(t *testing.T) {
	e, _ := mailEnv(t, false)
	e.zone.Set(pd, libdns.RR{Name: "portcullis", Type: "TXT", Data: "google-site-verification=abc123", TTL: time.Hour},
		libdns.RR{Name: "portcullis", Type: "TXT", Data: "v=spf1 include:_spf.example.net -all", TTL: time.Hour},
		libdns.RR{Name: "portcullis", Type: "MX", Data: "10 mx.example.net.", TTL: time.Hour})
	ctx := context.Background()
	pre := Build(ctx, e.in)
	it := find(t, pre, SetMail, pd, "TXT", StatusWrong)
	if !strings.Contains(strings.Join(it.Steps, "\n"), "replaces your SPF record v=spf1 include:_spf.example.net -all (other TXT records stay)") {
		t.Fatalf("steps %v", it.Steps)
	}
	if _, _, err := Apply(ctx, e.in, []string{SetMail}); err != nil {
		t.Fatal(err)
	}
	if got := rrs(e.zone, pd, "TXT"); len(got) != 2 || !strings.HasPrefix(got[0], "google-site-verification=abc123 ") || !strings.HasPrefix(got[1], "v=spf1 mx -all ") {
		t.Fatalf("TXT at %s = %v", pd, got)
	}
	if got := rrs(e.zone, pd, "MX"); len(got) != 1 || got[0] != "10 "+mh+". 1h0m0s" {
		t.Fatalf("MX = %v", got)
	}
	assertMailOK(t, Build(ctx, e.in))
}

// TestMailTLSAProviderCannotWrite: a provider that can't write TLSA gets
// the TLSA as a manual step; the rest is written.
func TestMailTLSAProviderCannotWrite(t *testing.T) {
	e, _ := mailEnv(t, false)
	e.in.Provider = &fakedns.Provider{Zone: e.zone, ZoneName: pz, RefuseTypes: []string{"TLSA"}}
	e.in.NoWrite = []string{"TLSA"}
	ctx := context.Background()
	if _, _, err := Apply(ctx, e.in, []string{SetMail}); err != nil {
		t.Fatal(err)
	}
	if got := e.zone.Records("_25._tcp." + mh); len(got) != 0 {
		t.Fatalf("TLSA written: %v", got)
	}
	it := find(t, Build(ctx, e.in), SetMail, "_25._tcp."+mh, "TLSA", StatusMissing)
	want := "add TLSA _25._tcp." + mh + " 3 1 1 " + spki + " by hand: fake can't write TLSA records"
	if it.Fix != FixManual || len(it.Steps) != 1 || it.Steps[0] != want {
		t.Fatalf("TLSA item %+v, want the step %q", it, want)
	}
	if find(t, Build(ctx, e.in), SetMail, dkimRS, "TXT", StatusOK).Fix != FixNone {
		t.Fatal("the DKIM item isn't ok")
	}
}

func TestValidateMailRefuses(t *testing.T) {
	const e = "team-b.example.test"
	good := []MailRecord{
		{Name: e, Type: "MX", TTL: 3600, Value: "10 " + mh + "."},
		{Name: e, Type: "TXT", TTL: 3600, Value: "v=spf1 mx -all"},
		{Name: "mta-sts." + e, Type: "CNAME", TTL: 3600, Value: mh + "."},
		{Name: "v1-rsa-20261115-2._domainkey." + e, Type: "TXT", TTL: 3600, Value: rsaTXT()},
	}
	if err := ValidateMail(e, good); err != nil {
		t.Fatalf("good set refused: %v", err)
	}
	with := func(r ...MailRecord) []MailRecord { return append(append([]MailRecord(nil), good...), r...) }
	many := append([]MailRecord(nil), good...)
	for len(many) <= MaxMailRecords {
		many = append(many, MailRecord{Name: "_dmarc." + e, Type: "TXT", TTL: 3600, Value: fmt.Sprintf("v=DMARC1; p=none; x=%d", len(many))})
	}
	for name, c := range map[string]struct {
		recs []MailRecord
		want string
	}{
		"outside":   {with(MailRecord{Name: "_dmarc.other.example.test", Type: "TXT", TTL: 3600, Value: "v=DMARC1; p=none"}), "not at or under " + e},
		"cname+txt": {with(MailRecord{Name: "mta-sts." + e, Type: "TXT", TTL: 3600, Value: "x"}), "a CNAME can't share mta-sts." + e},
		"201":       {many, "more than 200 records"},
		"caa at e":  {with(MailRecord{Name: e, Type: "CAA", TTL: 300, Value: `0 issue "letsencrypt.org"`}), "never holds CAA"},
		"caa at h":  {with(MailRecord{Name: "mail." + e, Type: "CAA", TTL: 300, Value: `0 issue "letsencrypt.org"`}), "never holds CAA"},
		"ttl":       {with(MailRecord{Name: "_smtp._tls." + e, Type: "TXT", TTL: 0, Value: "v=TLSRPTv1; rua=mailto:x@" + e}), "TTL 0"},
		"a":         {with(MailRecord{Name: "mail." + e, Type: "A", TTL: 300, Value: "203.0.113.10"}), "type A"},
		"txt at e":  {with(MailRecord{Name: e, Type: "TXT", TTL: 3600, Value: "google-site-verification=x"}), "only an SPF"},
		"quote":     {with(MailRecord{Name: "_dmarc." + e, Type: "TXT", TTL: 3600, Value: `v=DMARC1; "p=none"`}), "quote"},
		"h names":   {with(MailRecord{Name: "_25._tcp." + mh, Type: "TLSA", TTL: 3600, Value: "3 1 1 " + spki}), "not at or under " + e},
		"tlsa hex":  {with(MailRecord{Name: "_25._tcp.mail." + e, Type: "TLSA", TTL: 3600, Value: "3 1 1 zz"}), "TLSA"},
		"other srv": {with(MailRecord{Name: "_xmpp._tcp." + e, Type: "SRV", TTL: 3600, Value: "0 0 5222 " + mh + "."}), "not a name the mail set uses"},
	} {
		err := ValidateMail(e, c.recs)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	// The main domain may name MAIL_HOSTNAME (its MX target) outside <d>.
	var m []MailRecord
	for _, r := range mainMail() {
		r.Name = strings.ReplaceAll(r.Name, mh, "mail.example.test")
		r.Value = strings.ReplaceAll(r.Value, mh, "mail.example.test")
		m = append(m, r)
	}
	if err := ValidateMainMail(pd, "mail.example.test", m); err != nil {
		t.Fatalf("main set refused: %v", err)
	}
	if err := ValidateMail(pd, m); err == nil {
		t.Fatal("an added domain's set named MAIL_HOSTNAME outside it")
	}
	// MAIL_HOSTNAME is explicit: never the MX target's guess.
	if err := ValidateMainMail(pd, mh, m); err == nil || !strings.Contains(err.Error(), "not mail_hostname") {
		t.Fatalf("MX at another host: %v", err)
	}
	if err := ValidateMainMail(pd, "", nil); err == nil {
		t.Fatal("no mail_hostname accepted")
	}
}

// TestMailRemovalBringsNoMailBack: mail off with nomail back removes the
// mail records (a retired DKIM key too) and writes nomail; other TXT,
// address and CAA records stay.
func TestMailRemovalBringsNoMailBack(t *testing.T) {
	e, _ := mailEnv(t, true)
	e.addr(pd, ipv4)
	e.ourCAA()
	e.zone.Set(pd, append(e.zone.Records(pd), libdns.RR{Name: "portcullis", Type: "TXT", Data: "google-site-verification=abc123", TTL: time.Hour})...)
	ctx := context.Background()
	if _, _, err := Apply(ctx, e.in, []string{SetMail}); err != nil {
		t.Fatal(err)
	}
	// A rotation drops the old RSA selector: its TXT goes.
	rot := mainMail()
	rot[3].Name = "v1-rsa-20270514._domainkey." + pd
	e.in.Spec.Mail = rot
	_, removed, err := Apply(ctx, e.in, []string{SetMail})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.zone.Records(dkimRS)) != 0 || len(e.zone.Records(rot[3].Name)) != 1 {
		t.Fatalf("rotation: old %v new %v", e.zone.Records(dkimRS), e.zone.Records(rot[3].Name))
	}
	if len(removed) != 1 || removed[0].Type != "TXT" {
		t.Fatalf("removed %+v", removed)
	}
	assertMailOK(t, Build(ctx, e.in))
	// Off: nomail first, then the mail set's removal.
	e.in.Spec.Mail, e.in.Spec.NoMail = nil, true
	if _, _, err := Apply(ctx, e.in, []string{SetNoMail, SetMail}); err != nil {
		t.Fatal(err)
	}
	if got := rrs(e.zone, pd, "MX"); len(got) != 1 || !strings.HasPrefix(got[0], "0 . ") {
		t.Fatalf("MX = %v", got)
	}
	if got := rrs(e.zone, pd, "TXT"); len(got) != 2 || !strings.HasPrefix(got[1], "v=spf1 -all ") {
		t.Fatalf("TXT = %v", got)
	}
	if got := rrs(e.zone, "_dmarc."+pd, "TXT"); len(got) != 1 || !strings.HasPrefix(got[0], dmarcReject) {
		t.Fatalf("DMARC = %v", got)
	}
	for _, n := range []string{rot[3].Name, dkimED, "_smtp._tls." + pd, "_submissions._tcp." + pd, "_imap._tcp." + pd} {
		if got := e.zone.Records(n); len(got) != 0 {
			t.Errorf("%s left: %v", n, got)
		}
	}
	if len(rrs(e.zone, pd, "A")) != 1 || len(rrs(e.zone, pd, "CAA")) != 2 {
		t.Fatalf("address / caa touched: %v", e.zone.Records(pd))
	}
}

// TestMailApplyRefusesCNAMENextToRecords: a mail CNAME can't go where the
// zone already has another record (nothing written).
func TestMailApplyRefusesCNAMENextToRecords(t *testing.T) {
	e, ops := mailEnv(t, false)
	e.in.Spec.Main = false
	e.in.Spec.Mail = []MailRecord{
		{Name: pd, Type: "MX", TTL: 3600, Value: "10 " + mh + "."},
		{Name: "autoconfig." + pd, Type: "CNAME", TTL: 3600, Value: mh + "."},
	}
	e.addr("autoconfig."+pd, ipv4)
	_, _, err := Apply(context.Background(), e.in, []string{SetMail})
	if err == nil || !strings.Contains(err.Error(), "autoconfig."+pd) {
		t.Fatalf("= %v", err)
	}
	if ops.writes() != 0 {
		t.Fatal("something was written")
	}
}

// TestMailCNAMEsNotForeign (P44): the mail set's CNAMEs aren't foreign
// items; they are judged by the mail set.
func TestMailCNAMEsNotForeign(t *testing.T) {
	e, _ := mailEnv(t, false)
	e.in.Spec.Main = false
	e.in.Spec.Mail = []MailRecord{
		{Name: pd, Type: "MX", TTL: 3600, Value: "10 " + mh + "."},
		{Name: "mta-sts." + pd, Type: "CNAME", TTL: 3600, Value: mh + "."},
	}
	ctx := context.Background()
	if _, _, err := Apply(ctx, e.in, []string{SetMail}); err != nil {
		t.Fatal(err)
	}
	p := Build(ctx, e.in)
	for _, it := range p.Items {
		if it.Status == StatusForeign && it.Name == "mta-sts."+pd {
			t.Fatalf("foreign item %+v", it)
		}
	}
	find(t, p, SetMail, "mta-sts."+pd, "CNAME", StatusOK)
}

func hostRecords(e *env, h string) (spf, tlsa []string) {
	for _, rr := range e.zone.Records(h) {
		if rr.Type == "TXT" {
			spf = append(spf, rr.Data)
		}
	}
	for _, rr := range e.zone.Records("_25._tcp." + h) {
		tlsa = append(tlsa, rr.Data)
	}
	return spf, tlsa
}

// TestMainMailEmptyRemovesHostRecords: the main domain's set turned off
// (empty, mail_hostname given) removes MAIL_HOSTNAME's HELO SPF and TLSA
// with the rest; another TXT at the host stays.
func TestMainMailEmptyRemovesHostRecords(t *testing.T) {
	e, _ := mailEnv(t, false)
	e.zone.Set(mh, libdns.RR{Name: "mail.portcullis", Type: "TXT", Data: "keep=me", TTL: time.Hour})
	ctx := context.Background()
	if _, _, err := Apply(ctx, e.in, []string{SetMail}); err != nil {
		t.Fatal(err)
	}
	if spf, tlsa := hostRecords(e, mh); len(spf) != 2 || len(tlsa) != 1 {
		t.Fatalf("after apply: %v %v", spf, tlsa)
	}
	e.in.Spec.Mail = []MailRecord{}
	if _, _, err := Apply(ctx, e.in, []string{SetMail}); err != nil {
		t.Fatal(err)
	}
	if spf, tlsa := hostRecords(e, mh); len(spf) != 1 || spf[0] != "keep=me" || len(tlsa) != 0 {
		t.Fatalf("after mail off: TXT %v TLSA %v", spf, tlsa)
	}
	if got := e.zone.Records(pd); len(got) != 0 {
		t.Fatalf("left at %s: %v", pd, got)
	}
	// Without mail_hostname the main domain's set is refused.
	e.in.Spec.MailHost = ""
	if _, _, err := Apply(ctx, e.in, []string{SetMail}); err == nil || !strings.Contains(err.Error(), "mail_hostname") {
		t.Fatalf("no mail_hostname: %v", err)
	}
}

// TestMainMailHostChangeRemovesOld: MAIL_HOSTNAME changed — the old host's
// HELO SPF and TLSA go (found through the live MX and its exact HELO SPF),
// the new host's are written; the old host's other TXT stays.
func TestMainMailHostChangeRemovesOld(t *testing.T) {
	e, _ := mailEnv(t, true)
	e.zone.Set(mh, libdns.RR{Name: "mail.portcullis", Type: "TXT", Data: "keep=me", TTL: time.Hour})
	ctx := context.Background()
	if _, _, err := Apply(ctx, e.in, []string{SetMail}); err != nil {
		t.Fatal(err)
	}
	const nh = "mx." + pd
	var moved []MailRecord
	for _, r := range mainMail() {
		r.Name = strings.ReplaceAll(r.Name, mh, nh)
		r.Value = strings.ReplaceAll(r.Value, mh, nh)
		moved = append(moved, r)
	}
	e.in.Spec.Mail, e.in.Spec.MailHost = moved, nh
	// The CLI recorded the old host (secrets/mail/former-hostnames).
	e.in.Spec.FormerMailHosts = []string{mh}
	pre := Build(ctx, e.in)
	find(t, pre, SetMail, "_25._tcp."+mh, "TLSA", StatusWrong)
	if _, _, err := Apply(ctx, e.in, []string{SetMail}); err != nil {
		t.Fatal(err)
	}
	if spf, tlsa := hostRecords(e, mh); len(spf) != 1 || spf[0] != "keep=me" || len(tlsa) != 0 {
		t.Fatalf("old host: TXT %v TLSA %v", spf, tlsa)
	}
	if spf, tlsa := hostRecords(e, nh); len(spf) != 1 || spf[0] != heloSPF || len(tlsa) != 1 {
		t.Fatalf("new host: TXT %v TLSA %v", spf, tlsa)
	}
	if got := rrs(e.zone, pd, "MX"); len(got) != 1 || !strings.HasPrefix(got[0], "10 "+nh+". ") {
		t.Fatalf("MX %v", got)
	}
	p := Build(ctx, e.in)
	assertMailOK(t, p)
	for _, it := range p.Items {
		if it.Name == mh || it.Name == "_25._tcp."+mh {
			t.Fatalf("an item for the old host after the move: %+v", it)
		}
	}
}

// TestMainMailOwnMXHostUntouched: a user's own mail host (a live MX at d
// whose TXT isn't the set's exact HELO SPF) is not taken for an old
// MAIL_HOSTNAME: its SPF and TLSA stay when mail goes on.
func TestMainMailOwnMXHostUntouched(t *testing.T) {
	e, _ := mailEnv(t, false)
	const own = "mx1." + pd
	e.zone.Set(pd, libdns.RR{Name: "portcullis", Type: "MX", Data: "10 " + own + ".", TTL: time.Hour})
	e.zone.Set(own, libdns.RR{Name: "mx1.portcullis", Type: "TXT", Data: "v=spf1 ip4:198.51.100.7 -all", TTL: time.Hour})
	e.zone.Set("_25._tcp."+own, libdns.RR{Name: "_25._tcp.mx1.portcullis", Type: "TLSA", Data: "3 1 1 " + strings.Repeat("ab", 32), TTL: time.Hour})
	if _, _, err := Apply(context.Background(), e.in, []string{SetMail}); err != nil {
		t.Fatal(err)
	}
	if spf, tlsa := hostRecords(e, own); len(spf) != 1 || len(tlsa) != 1 {
		t.Fatalf("own host touched: TXT %v TLSA %v", spf, tlsa)
	}
}

// Final review L7: an operator's own MX host carrying exactly the set's
// HELO SPF is not adopted unless the CLI recorded it as a former
// MAIL_HOSTNAME: its SPF and TLSA stay when mail goes on.
func TestMainMailSameSPFHostNotAdoptedUnlessRecorded(t *testing.T) {
	e, _ := mailEnv(t, false)
	const own = "mx1." + pd
	e.zone.Set(pd, libdns.RR{Name: "portcullis", Type: "MX", Data: "10 " + own + ".", TTL: time.Hour})
	e.zone.Set(own, libdns.RR{Name: "mx1.portcullis", Type: "TXT", Data: heloSPF, TTL: time.Hour})
	e.zone.Set("_25._tcp."+own, libdns.RR{Name: "_25._tcp.mx1.portcullis", Type: "TLSA", Data: "3 1 1 " + strings.Repeat("ab", 32), TTL: time.Hour})
	if _, _, err := Apply(context.Background(), e.in, []string{SetMail}); err != nil {
		t.Fatal(err)
	}
	if spf, tlsa := hostRecords(e, own); len(spf) != 1 || len(tlsa) != 1 {
		t.Fatalf("an unrecorded host with the same SPF was adopted: TXT %v TLSA %v", spf, tlsa)
	}
}

// A set the provider refuses doesn't keep the other sets from being
// written (test server 2026-11-16: Porkbun refused the mail set's MX); the
// error names the failed set, and a set after it still goes.
func TestApplyFailedSetDoesNotStopTheOthers(t *testing.T) {
	e, _ := mailEnv(t, false)
	e.in.Provider = &fakedns.Provider{Zone: e.zone, ZoneName: pz, Hook: func(op string, recs []libdns.Record) error {
		for _, r := range recs {
			if op == "append" && r.RR().Type == "MX" {
				return errors.New("Create error: We were unable to create the DNS record.")
			}
		}
		return nil
	}}
	_, _, err := Apply(context.Background(), e.in, []string{SetMail, SetAddress})
	if err == nil || !strings.Contains(err.Error(), "unable to create") {
		t.Fatalf("want the mail set's error, got %v", err)
	}
	if got := rrs(e.zone, mh, "A"); len(got) != 1 {
		t.Fatalf("the address set after the failed mail set wasn't written: A at %s = %v", mh, got)
	}
	if got := rrs(e.zone, pd, "MX"); len(got) != 0 {
		t.Fatalf("MX %v", got)
	}
}

// M5: any provider's DKIM selector (one DNS label) is accepted and owned
// by the set (so a stale one is cleaned up); a dotted selector is not.
func TestMailAnyDKIMSelector(t *testing.T) {
	const e = "team-b.example.test"
	recs := []MailRecord{
		{Name: e, Type: "MX", TTL: 3600, Value: "10 " + mh + "."},
		{Name: "google._domainkey." + e, Type: "TXT", TTL: 300, Value: rsaTXT()},
		{Name: "s1._domainkey." + e, Type: "TXT", TTL: 300, Value: rsaTXT()},
	}
	if err := ValidateMail(e, recs); err != nil {
		t.Fatalf("a non-mailctl selector refused: %v", err)
	}
	for _, n := range []string{"google._domainkey." + e, "s1._domainkey." + e, "selector_2._domainkey." + e} {
		if !MailNameOwned(e, n) {
			t.Errorf("%s not owned by the mail set", n)
		}
	}
	if MailNameOwned(e, "a.b._domainkey."+e) {
		t.Error("a dotted selector is owned")
	}
}
