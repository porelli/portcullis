package dnsplan

// The mail record set (contract §19.7, §12.2 / §12.4): the records the
// wired mail provider renders for a mail domain — MX, SPF, DKIM, DMARC,
// MTA-STS, TLS-RPT, SRV, the mail CNAMEs — judged by the shared rules
// (mailrules.go), and, for the main domain, core's HELO SPF and TLSA at
// MAIL_HOSTNAME (tlsa.go). The set replaces nomail while it is on. It
// owns exactly the names of the contract's table (below), so a record it
// stops wanting (a retired DKIM selector, a withheld TLSA) is removed; it
// never touches A / AAAA / CAA (the address and caa sets) and, at <e> and
// MAIL_HOSTNAME, only the SPF string of the TXT records.

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
	"github.com/miekg/dns"
)

// SetMail is the mail record set.
const SetMail = "mail"

// MaxMailRecords bounds one mail set (contract §12.2).
const MaxMailRecords = 200

const (
	// Any provider's TTLs (M5: parity with the shared rules; never 0).
	mailTTLMin = 1
	mailTTLMax = 86400
	// mailTXTMax bounds one TXT value (an RSA-4096 DKIM key fits).
	mailTXTMax = 2048
)

// MailRecord is one wanted record of the mail set (absolute name without
// the trailing dot, TTL in seconds, the value in zone-file form: MX
// "10 mail.example.org.", SRV "0 1 465 mail.example.org.", TLSA
// "3 1 1 <hex>", CNAME "mail.example.org.", TXT the text unquoted).
type MailRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   int    `json:"ttl"`
	Value string `json:"value"`
}

var (
	// dkimLabel: any provider's DKIM selector, one DNS label (M5: parity
	// with the shared rules; the set owns every <sel>._domainkey.<e>).
	dkimLabel = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$`)
	// mailTXTLabels / mailSRVLabels / mailCNAMELabels: the other names
	// under <e> the set owns, by type.
	mailTXTLabels   = []string{"_dmarc", "_mta-sts", "_smtp._tls"}
	mailSRVLabels   = []string{"_submissions._tcp", "_imaps._tcp", "_submission._tcp", "_imap._tcp", "_pop3._tcp", "_pop3s._tcp"}
	mailCNAMELabels = []string{"mta-sts", "autoconfig", "autodiscover"}
	mailTypes       = []string{"MX", "TXT", "SRV", "TLSA", "CNAME"}
)

// ValidateMail checks an added domain's mail set for d (PUT
// /domains/{name}/sets/mail): every name at or under d and one the set
// owns for its type, types MX / TXT / SRV / TLSA / CNAME only (never CAA:
// the CAA at MAIL_HOSTNAME is mail-cert's), TTL 60–86400, at most 200
// records, no CNAME next to another type at one name, and well-formed
// values.
func ValidateMail(d string, recs []MailRecord) error { return validateMail(d, "", recs) }

// ValidateMainMail is ValidateMail for the main domain, whose set may also
// name host — MAIL_HOSTNAME, given explicitly (dns-tool's mail_hostname),
// never derived — for its HELO SPF and its TLSA (`_25._tcp.<host>`), also
// outside d; every MX of the set targets it.
func ValidateMainMail(d, host string, recs []MailRecord) error {
	host = bare(host)
	if !validName(host) || strings.HasPrefix(host, "_") {
		return fmt.Errorf("mail_hostname %q is not a valid host name", host)
	}
	return validateMail(d, host, recs)
}

func validateMail(d, host string, recs []MailRecord) error {
	d = bare(d)
	if len(recs) > MaxMailRecords {
		return fmt.Errorf("the mail set has more than %d records (%d)", MaxMailRecords, len(recs))
	}
	var hosts []string
	if host != "" {
		hosts = []string{host}
	}
	seen := map[string]bool{}
	types := map[string]map[string]bool{} // name → types
	for _, r := range recs {
		n, t := bare(r.Name), strings.ToUpper(r.Type)
		where := t + " " + n
		switch {
		case t == "CAA":
			return fmt.Errorf("%s: the mail set never holds CAA (the CAA at MAIL_HOSTNAME is mail-cert's)", where)
		case !contains(mailTypes, t):
			return fmt.Errorf("%s: type %s isn't one of %s", where, r.Type, strings.Join(mailTypes, ", "))
		case r.TTL < mailTTLMin || r.TTL > mailTTLMax:
			return fmt.Errorf("%s: TTL %d outside %d–%d", where, r.TTL, mailTTLMin, mailTTLMax)
		case !validName(n):
			return fmt.Errorf("%s: not a valid DNS name", where)
		case !under(n, d) && !hostName(n, hosts):
			return fmt.Errorf("%s: not at or under %s", where, d)
		}
		v, err := canonMail(t, r.Value)
		if err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		if t == "MX" && host != "" && strings.Fields(v)[1] != fqdn(host) {
			return fmt.Errorf("%s: the MX targets %s, not mail_hostname %s", where, strings.Fields(v)[1], host)
		}
		k := n + " " + t + " " + v
		if seen[k] {
			return fmt.Errorf("%s: %q twice", where, r.Value)
		}
		seen[k] = true
		if types[n] == nil {
			types[n] = map[string]bool{}
		}
		types[n][t] = true
	}
	for n, ts := range types {
		if ts["CNAME"] && len(ts) > 1 {
			return fmt.Errorf("CNAME %s: a CNAME can't share %s with another type", n, n)
		}
	}
	spf := map[string]int{}
	for _, r := range recs {
		n, t := bare(r.Name), strings.ToUpper(r.Type)
		if !mailOwns(d, hosts, n, t) {
			return fmt.Errorf("%s %s: not a name the mail set uses for %s (contract §19.7)", t, n, t)
		}
		if t == "TXT" && txtSPFOnly(d, hosts, n) {
			if !isSPF(r.Value) {
				return fmt.Errorf("TXT %s: the mail set holds only an SPF record there (other TXT records stay as they are)", n)
			}
			if spf[n]++; spf[n] > 1 {
				return fmt.Errorf("TXT %s: more than one SPF record", n)
			}
		}
	}
	return nil
}

func validName(n string) bool {
	if n == "" || len(n) > 253 {
		return false
	}
	_, ok := dns.IsDomainName(n)
	return ok && !strings.ContainsAny(n, " *\\\"")
}

// under: n is d or a name under it.
func under(n, d string) bool { return n == d || strings.HasSuffix(n, "."+d) }

// heloSPF is the HELO SPF the mail set writes at MAIL_HOSTNAME.
const heloSPF = "v=spf1 a -all"

// liveHosts: MAIL_HOSTNAME (the spec's, main domain only) plus a previous
// one: a target of a live MX at d other than it, recorded as a former
// MAIL_HOSTNAME (FormerMailHosts; final review L7: an operator's own MX
// host with the same SPF is never adopted), whose TXT holds exactly
// the set's HELO SPF — after a MAIL_HOSTNAME change the old host's HELO
// SPF and TLSA are the set's to remove. Only names the provider read
// (at or under d or MAIL_HOSTNAME) count.
func liveHosts(s Spec, d string, live []liveRec) []string {
	hosts := specHosts(s, d)
	if len(hosts) == 0 {
		return nil
	}
	for _, rr := range pick(live, d, "MX") {
		f := strings.Fields(rr.Data)
		if len(f) != 2 || f[1] == "." {
			continue
		}
		x := bare(f[1])
		if contains(hosts, x) || !contains(bareAll(s.FormerMailHosts), x) {
			continue
		}
		for _, t := range pick(live, x, "TXT") {
			if txtJoin(t.Data) == heloSPF {
				hosts = append(hosts, x)
				break
			}
		}
	}
	return hosts
}

func bareAll(ns []string) []string {
	out := make([]string, 0, len(ns))
	for _, n := range ns {
		out = append(out, bare(n))
	}
	return out
}

// hostName: n is one of MAIL_HOSTNAME's names (the host or its TLSA owner).
func hostName(n string, hosts []string) bool {
	for _, h := range hosts {
		if n == h || n == "_25._tcp."+h {
			return true
		}
	}
	return false
}

// mailOwns: the (name, type) RRset belongs to the mail set at d (hosts:
// MAIL_HOSTNAME, main domain only).
func mailOwns(d string, hosts []string, n, t string) bool {
	switch t {
	case "MX":
		return n == d
	case "TXT":
		if n == d || contains(hosts, n) {
			return true
		}
		for _, l := range mailTXTLabels {
			if n == l+"."+d {
				return true
			}
		}
		if sel, ok := strings.CutSuffix(n, "._domainkey."+d); ok {
			return dkimLabel.MatchString(sel)
		}
	case "SRV":
		for _, l := range mailSRVLabels {
			if n == l+"."+d {
				return true
			}
		}
	case "CNAME":
		for _, l := range mailCNAMELabels {
			if n == l+"."+d {
				return true
			}
		}
	case "TLSA":
		for _, h := range hosts {
			if n == "_25._tcp."+h {
				return true
			}
		}
	}
	return false
}

// txtSPFOnly: at n the mail set owns only the SPF string of the TXT
// records (<e> and MAIL_HOSTNAME): other TXT records stay.
func txtSPFOnly(d string, hosts []string, n string) bool { return n == d || contains(hosts, n) }

// isDKIMName: n is <selector>._domainkey.<d>.
func isDKIMName(d, n string) bool {
	sel, ok := strings.CutSuffix(n, "._domainkey."+d)
	return ok && dkimLabel.MatchString(sel)
}

// DKIMNames: the <selector>._domainkey.<d> names among recs (what the
// caller records as written once the set is applied).
func DKIMNames(d string, recs []MailRecord) []string {
	d = bare(d)
	var out []string
	for _, r := range recs {
		if n := bare(r.Name); strings.EqualFold(r.Type, "TXT") && isDKIMName(d, n) && !contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// mailNameOwned: n is a name the mail set may write at d (any type).
func mailNameOwned(d string, hosts []string, n string) bool {
	for _, t := range mailTypes {
		if mailOwns(d, hosts, n, t) {
			return true
		}
	}
	return false
}

// canonMail is a value in the one form the plan compares: lowercase
// FQDN targets, TLSA hex lowercase, TXT as is.
func canonMail(t, v string) (string, error) {
	f := strings.Fields(v)
	target := func(s string) (string, error) {
		if s == "." {
			return ".", nil
		}
		if _, ok := dns.IsDomainName(s); !ok || strings.ContainsAny(s, "*\\\"") {
			return "", fmt.Errorf("%q isn't a host name", s)
		}
		return fqdn(s), nil
	}
	u16 := func(s string) (uint64, error) { return strconv.ParseUint(s, 10, 16) }
	switch t {
	case "MX":
		if len(f) != 2 {
			return "", errors.New(`an MX value is "<preference> <host>."`)
		}
		p, err := u16(f[0])
		if err != nil {
			return "", fmt.Errorf("MX preference %q", f[0])
		}
		h, err := target(f[1])
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d %s", p, h), nil
	case "SRV":
		if len(f) != 4 {
			return "", errors.New(`an SRV value is "<priority> <weight> <port> <host>."`)
		}
		var n [3]uint64
		for i := range 3 {
			x, err := u16(f[i])
			if err != nil {
				return "", fmt.Errorf("SRV field %q", f[i])
			}
			n[i] = x
		}
		h, err := target(f[3])
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d %d %d %s", n[0], n[1], n[2], h), nil
	case "TLSA":
		if len(f) != 4 {
			return "", errors.New(`a TLSA value is "<usage> <selector> <matching type> <hex>"`)
		}
		var n [3]uint64
		for i := range 3 {
			x, err := strconv.ParseUint(f[i], 10, 8)
			if err != nil {
				return "", fmt.Errorf("TLSA field %q", f[i])
			}
			n[i] = x
		}
		h := strings.ToLower(f[3])
		if _, err := hex.DecodeString(h); err != nil || h == "" {
			return "", errors.New("the TLSA data isn't hex")
		}
		return fmt.Sprintf("%d %d %d %s", n[0], n[1], n[2], h), nil
	case "CNAME":
		if len(f) != 1 || f[0] == "." {
			return "", errors.New("a CNAME value is one host name")
		}
		return target(f[0])
	case "TXT":
		switch {
		case v == "" || len(v) > mailTXTMax:
			return "", fmt.Errorf("a TXT value has 1–%d bytes", mailTXTMax)
		case strings.ContainsAny(v, "\"\\"):
			return "", errors.New("a TXT value holds no quote or backslash")
		}
		for i := 0; i < len(v); i++ {
			if v[i] < 0x20 || v[i] > 0x7e {
				return "", errors.New("a TXT value is printable ASCII")
			}
		}
		return v, nil
	}
	return "", fmt.Errorf("type %s", t)
}

// canonLive is a served or stored value in canonMail's form (unparsable
// values stay as they are: they never equal a wanted one).
func canonLive(t, v string) string {
	if t == "TXT" {
		return txtJoin(v)
	}
	if c, err := canonMail(t, v); err == nil {
		return c
	}
	return strings.TrimSpace(v)
}

// mailRecords turns the records into libdns records (absolute names with
// a trailing dot, as Wanted): a TXT stays one value (the provider path
// splits it into ≤ 255-byte strings; it is compared joined), TLSA is a
// libdns.RR {Type: "TLSA", Data: "3 1 1 <hex>"}.
func mailRecords(recs []MailRecord) ([]libdns.Record, error) {
	out := make([]libdns.Record, 0, len(recs))
	for _, r := range recs {
		t := strings.ToUpper(r.Type)
		v, err := canonMail(t, r.Value)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", t, bare(r.Name), err)
		}
		n := fqdn(r.Name)
		ttl := time.Duration(r.TTL) * time.Second
		f := strings.Fields(v)
		switch t {
		case "MX":
			p, _ := strconv.ParseUint(f[0], 10, 16)
			out = append(out, libdns.MX{Name: n, TTL: ttl, Preference: uint16(p), Target: f[1]})
		case "TXT":
			out = append(out, libdns.TXT{Name: n, TTL: ttl, Text: v})
		case "CNAME":
			out = append(out, libdns.CNAME{Name: n, TTL: ttl, Target: v})
		case "SRV":
			labels := strings.SplitN(n, ".", 3)
			if len(labels) != 3 || !strings.HasPrefix(labels[0], "_") || !strings.HasPrefix(labels[1], "_") {
				return nil, fmt.Errorf("SRV %s: the name isn't _<service>._<proto>.<domain>", bare(n))
			}
			var x [3]uint64
			for i := range 3 {
				x[i], _ = strconv.ParseUint(f[i], 10, 16)
			}
			out = append(out, libdns.SRV{Service: labels[0][1:], Transport: labels[1][1:], Name: labels[2], TTL: ttl,
				Priority: uint16(x[0]), Weight: uint16(x[1]), Port: uint16(x[2]), Target: f[3]})
		case "TLSA":
			out = append(out, libdns.RR{Name: n, TTL: ttl, Type: "TLSA", Data: v})
		}
	}
	return out, nil
}

// mailPair is one (name, type) RRset of the mail set.
type mailPair struct{ name, typ string }

// mailPairs: the wanted RRsets of the set, in the set's order, then every
// other RRset it owns that the provider holds (stale: to be removed).
// With nomail on and no mail wanted, nomail's RRsets aren't the mail
// set's to remove.
func mailPairs(s Spec, d string, hosts []string, live []liveRec) []mailPair {
	var out []mailPair
	seen := map[mailPair]bool{}
	add := func(p mailPair) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, r := range s.Mail {
		add(mailPair{bare(r.Name), strings.ToUpper(r.Type)})
	}
	var stale []mailPair
	for _, l := range live {
		p := mailPair{l.abs, strings.ToUpper(l.rr.Type)}
		if seen[p] || !mailOwns(d, hosts, p.name, p.typ) {
			continue
		}
		if p.typ == "TXT" && txtSPFOnly(d, hosts, p.name) && !isSPF(txtJoin(l.rr.Data)) {
			continue
		}
		if p.typ == "TXT" && isDKIMName(d, p.name) && !contains(bareAll(s.MailDKIMWritten), p.name) {
			continue
		}
		if len(s.Mail) == 0 && s.NoMail && nomailOwns(d, p) {
			continue
		}
		seen[p] = true
		stale = append(stale, p)
	}
	sort.Slice(stale, func(i, j int) bool {
		return stale[i].name < stale[j].name || stale[i].name == stale[j].name && stale[i].typ < stale[j].typ
	})
	return append(out, stale...)
}

// canonTarget is a target host as compared: "." or a lowercase FQDN.
func canonTarget(s string) string {
	if s == "." || s == "" {
		return "."
	}
	return fqdn(s)
}

// nomailOwns: the RRsets nomail writes at d.
func nomailOwns(d string, p mailPair) bool {
	return p == mailPair{d, "MX"} || p == mailPair{d, "TXT"} || p == mailPair{"_dmarc." + d, "TXT"}
}

// specHosts: MAIL_HOSTNAME's names for the spec (main domain only: an
// added domain's set never names them).
func specHosts(s Spec, d string) []string {
	if !s.Main || s.MailHost == "" {
		return nil
	}
	return []string{bare(s.MailHost)}
}

// cannotWrite: the provider can't write type t (Input.NoWrite).
func (in Input) cannotWrite(t string) bool {
	for _, x := range in.NoWrite {
		if strings.EqualFold(x, t) {
			return true
		}
	}
	return false
}

func qtypeOf(t string) uint16 { return dns.StringToType[t] }

// mailItems: one item per (name, type) the set wants, judged by judge at
// every resolver, plus one per stale RRset the provider still holds.
func mailItems(ctx context.Context, in Input, d string, fix Fix, live []liveRec) []Item {
	s := in.Spec
	hosts := liveHosts(s, d, live)
	want := map[mailPair][]string{}
	ttl := map[mailPair]int{}
	for _, r := range s.Mail {
		p := mailPair{bare(r.Name), strings.ToUpper(r.Type)}
		v, err := canonMail(p.typ, r.Value)
		if err != nil {
			v = r.Value
		}
		want[p] = append(want[p], v)
		if _, ok := ttl[p]; !ok {
			ttl[p] = r.TTL
		}
	}
	var out []Item
	for _, p := range mailPairs(s, d, hosts, live) {
		w := want[p]
		if w == nil {
			w = []string{}
		}
		it := Item{Set: SetMail, Name: p.name, Type: p.typ, Want: w, Live: []string{}, Steps: []string{}}
		v := lookup(ctx, in.Resolvers, p.name, qtypeOf(p.typ))
		if v.err == nil {
			spfOnly := p.typ == "TXT" && txtSPFOnly(d, hosts, p.name)
			for i, vals := range v.vals {
				var keep []string
				for _, x := range vals {
					x = canonLive(p.typ, x)
					if spfOnly && !isSPF(x) {
						continue
					}
					keep = append(keep, x)
				}
				sort.Strings(keep)
				v.vals[i] = keep
			}
		}
		it.Status, it.Live = judge(v, it.Want)
		// A stale RRset the provider still holds is wrong, whatever a
		// resolver caches.
		if len(w) == 0 && it.Status == StatusOK {
			var held []string
			for _, rr := range pick(live, p.name, p.typ) {
				held = append(held, canonLive(p.typ, rr.Data))
			}
			if len(held) > 0 {
				it.Status, it.Live = StatusWrong, held
			}
		}
		manual := in.cannotWrite(p.typ)
		switch it.Status {
		case StatusOK:
			it.Severity, it.Fix = SevOK, FixNone
		case StatusUnknown:
			it.Severity, it.Fix = SevWarning, FixNone
			it.Steps = []string{"lookup failed (retry): " + v.err.Error()}
		default:
			it.Severity, it.Fix = SevWarning, fix
			if it.Status == StatusWrong {
				it.Severity = SevProblem
			}
			t := time.Duration(ttl[p]) * time.Second
			if t == 0 {
				t = 3600 * time.Second
			}
			if manual {
				it.Fix = FixManual
				for _, x := range it.Want {
					if !contains(it.Live, x) {
						it.Steps = append(it.Steps, fmt.Sprintf("add %s %s %s by hand: %s can't write %s records", p.typ, p.name, x, providerLabel(in), p.typ))
					}
				}
				for _, x := range it.Live {
					if !contains(it.Want, x) {
						it.Steps = append(it.Steps, fmt.Sprintf("remove %s %s %s by hand: %s can't write %s records", p.typ, p.name, x, providerLabel(in), p.typ))
					}
				}
				break
			}
			it.Steps = diffSteps(p.typ, p.name, it.Want, it.Live, t)
			for _, l := range it.Live {
				if contains(it.Want, l) {
					continue
				}
				switch {
				case p.typ == "MX":
					it.Steps = append(it.Steps, fmt.Sprintf("replaces the MX record %s: mail for %s then goes to Portcullis", l, d))
				case p.typ == "TXT" && txtSPFOnly(d, hosts, p.name):
					it.Steps = append(it.Steps, "replaces your SPF record "+l+" (other TXT records stay)")
				case p.name == "_dmarc."+d:
					it.Steps = append(it.Steps, "replaces your DMARC record "+l)
				}
			}
		}
		out = append(out, it)
	}
	return out
}

func providerLabel(in Input) string {
	if in.ProviderName != "" {
		return in.ProviderName
	}
	return "your DNS provider"
}

// applyMail writes the mail set: per RRset the wanted records appended
// first, then the stale entries deleted by exact data (syncSet). At <e>
// and MAIL_HOSTNAME only the SPF string of the TXT records is the set's.
// RRsets of a type the provider can't write are left (the plan shows a
// manual step). A CNAME next to another record at its name, or a record
// next to a CNAME, is refused before anything is written.
func applyMail(ctx context.Context, in Input, d, zone string, live []liveRec) (written, removed []Ref, err error) {
	s := in.Spec
	recs, err := mailRecords(s.Mail)
	if err != nil {
		return nil, nil, err
	}
	hosts := liveHosts(s, d, live)
	for _, h := range hosts {
		if !under(h, bare(zone)) {
			return nil, nil, fmt.Errorf("MAIL_HOSTNAME %s isn't in the DNS zone %s of %s", h, bare(zone), d)
		}
	}
	byPair := map[mailPair][]libdns.Record{}
	for _, r := range recs {
		rr := r.RR()
		n := bare(libdns.AbsoluteName(rr.Name, zone))
		if srv, ok := r.(libdns.SRV); ok {
			n = bare("_" + srv.Service + "._" + srv.Transport + "." + srv.Name)
		}
		p := mailPair{n, rr.Type}
		byPair[p] = append(byPair[p], r)
	}
	pairs := mailPairs(s, d, hosts, live)
	// CNAMEs first checked against what the zone holds (fail closed).
	for _, p := range pairs {
		if len(byPair[p]) == 0 {
			continue
		}
		for _, l := range live {
			if l.abs != p.name {
				continue
			}
			lt := strings.ToUpper(l.rr.Type)
			if (p.typ == "CNAME") != (lt == "CNAME") {
				return nil, nil, fmt.Errorf("%s holds a %s record: the mail set can't put a %s next to it (remove it first)", p.name, lt, p.typ)
			}
		}
	}
	for _, p := range pairs {
		if in.cannotWrite(p.typ) {
			continue
		}
		want := byPair[p]
		for _, r := range want {
			written = append(written, RefOf(r, zone))
		}
		if p.typ == "TXT" && txtSPFOnly(d, hosts, p.name) {
			for _, rr := range pick(live, p.name, "TXT") {
				if !isSPF(txtJoin(rr.Data)) {
					want = append(want, libdns.RR{Name: p.name + ".", TTL: rr.TTL, Type: "TXT", Data: rr.Data})
				}
			}
		}
		del, err := syncSet(ctx, in.Provider, zone, p.name, p.typ, want, live)
		for _, g := range del {
			removed = append(removed, RefOf(g, zone))
		}
		if err != nil {
			return written, removed, fmt.Errorf("setting the mail records %s %s: %w", p.typ, p.name, err)
		}
	}
	return written, removed, nil
}

// txtJoin is a TXT value as its character-strings joined: the form
// `"a" "b"` (two or more quoted strings, as some providers return a long
// TXT) becomes "ab"; anything else stays as it is.
func txtJoin(v string) string {
	if !strings.HasPrefix(v, `"`) {
		return v
	}
	var parts []string
	rest := v
	for {
		q, err := strconv.QuotedPrefix(rest)
		if err != nil {
			return v
		}
		u, err := strconv.Unquote(q)
		if err != nil {
			return v
		}
		parts = append(parts, u)
		rest = rest[len(q):]
		if rest == "" {
			break
		}
		if !strings.HasPrefix(rest, ` "`) {
			return v
		}
		rest = rest[1:]
	}
	if len(parts) < 2 {
		return v
	}
	return strings.Join(parts, "")
}

// MailNameOwned: an added domain d's own mail set would use name n (any
// type): the names of the contract §19.7 table under d.
func MailNameOwned(d, n string) bool { return mailNameOwned(bare(d), nil, bare(n)) }
