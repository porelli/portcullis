package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/miekg/dns"

	"github.com/portcullis/mailctl/internal/state"
)

// DANE probes (security ruling): the good probe is the root DNSKEY with
// DO through mail-resolver (AD expected; no third party involved); a
// deliberately broken third-party name is only the control (SERVFAIL
// expected).
const (
	DANEGood   = "."
	DANEBroken = "fail01.dnssec.works"
)

// Switching DANE off needs DANEOffAfter consecutive definite
// not-validating verdicts spanning at least DANEOffSpan.
const (
	DANEOffAfter = 3
	DANEOffSpan  = 30 * time.Minute
)

const extDANE = "dane_streak"

// daneStreak is the run of definite not-validating verdicts.
type daneStreak struct {
	First *time.Time `json:"first"`
	Count int        `json:"count"`
}

// verdict: "valid", "invalid" (a definite not-validating answer) or
// "unknown" (anything else: errors, timeouts, other rcodes, SERVFAIL on
// the good probe).
func verdict(good, broken *dns.Msg) string {
	switch {
	case good == nil || broken == nil:
		return "unknown"
	case good.Rcode == dns.RcodeSuccess && good.AuthenticatedData && broken.Rcode == dns.RcodeServerFailure:
		return "valid"
	case good.Rcode == dns.RcodeSuccess && !good.AuthenticatedData && broken.Rcode == dns.RcodeSuccess:
		// The resolver answers both and validates neither.
		return "invalid"
	}
	return "unknown"
}

// clientIP: rewritten client addresses (rootless Podman) → Warning.
func clientIP(d Deps) Check {
	c := Check{ID: "client_ip", Severity: OK, Detail: "client addresses preserved"}
	if d.Cfg.ClientIP == "rewritten" {
		c.Severity = Warning
		c.Detail = "client addresses are rewritten (rootless Podman): SPF, iprev and the IP blocklists are off, DMARC never rejects, and nobody is banned automatically"
		c.Steps = []string{"Run the mail server under rootful Docker to see real client addresses (Portcullis never switches runtimes: backup, init with --runtime docker, restore)."}
	}
	return c
}

// dane: mail-resolver validates DNSSEC. Only definite verdicts act: the
// first valid one switches DANE on (every MtaTlsStrategy dane: optional);
// DANEOffAfter consecutive invalid ones over DANEOffSpan switch it off
// (MTA-STS and STARTTLS still apply); an unknown result changes nothing.
// While DANE is off the check is a Problem (mail_dane_off).
func dane(ctx context.Context, d Deps) Check {
	c := Check{ID: "dane"}
	good, gerr := askRetry(ctx, d, DANEGood, dns.TypeDNSKEY)
	broken, berr := askRetry(ctx, d, DANEBroken, dns.TypeA)
	if gerr != nil || berr != nil {
		good, broken = nil, nil
	}
	v := verdict(good, broken)
	now := d.now()
	var st daneStreak
	_ = json.Unmarshal(d.Store.Get().Ext[extDANE], &st)
	switch v {
	case "valid":
		st = daneStreak{}
		if err := setDANE(ctx, d, "optional"); err != nil {
			c.Severity, c.Detail = Warning, "mail-resolver validates DNSSEC, but switching DANE on failed: "+err.Error()
		}
	case "invalid":
		if st.First == nil {
			t := now
			st.First = &t
		}
		st.Count++
		if st.Count >= DANEOffAfter && now.Sub(*st.First) >= DANEOffSpan {
			if err := setDANE(ctx, d, "disable"); err != nil {
				c.Severity, c.Detail = Warning, "switching DANE off failed: "+err.Error()
			}
		}
	}
	_ = d.Store.Update(func(s *state.Persistent) error {
		b, _ := json.Marshal(st)
		s.Ext[extDANE] = b
		return nil
	})
	if c.Severity != "" {
		return c
	}
	off, err := daneOff(ctx, d)
	switch {
	case err != nil:
		c.Severity, c.Detail = Info, "the DANE setting couldn't be read"
	case off:
		c.Severity = Problem
		c.Detail = "DANE is off: the resolver can't validate DNSSEC"
		c.Steps = []string{"mail-resolver needs to reach the root servers over UDP and TCP port 53; check the host's firewall. DANE switches back on at the first check that validates."}
	case v == "valid":
		c.Severity, c.Detail = OK, "mail-resolver validates DNSSEC: outbound DANE is on"
	case v == "invalid":
		c.Severity = Warning
		c.Detail = fmt.Sprintf("mail-resolver didn't validate DNSSEC (%d time(s) in a row); DANE stays on until it fails %d times over %s", st.Count, DANEOffAfter, DANEOffSpan)
	default:
		c.Severity, c.Detail = Info, "mail-resolver gave no definite answer: DANE left as it was"
	}
	return c
}

// daneOff: Portcullis's strategies have DANE disabled.
func daneOff(ctx context.Context, d Deps) (bool, error) {
	ids, err := d.C.Query(ctx, "MtaTlsStrategy", nil)
	if err != nil || len(ids) == 0 {
		return false, err
	}
	var ss []struct {
		DANE string `json:"dane"`
	}
	if err := d.C.Get(ctx, "MtaTlsStrategy", ids, []string{"dane"}, &ss); err != nil {
		return false, err
	}
	for _, s := range ss {
		if s.DANE == "disable" {
			return true, nil
		}
	}
	return false, nil
}

func setDANE(ctx context.Context, d Deps, want string) error {
	ids, err := d.C.Query(ctx, "MtaTlsStrategy", nil)
	if err != nil || len(ids) == 0 {
		return err
	}
	var ss []struct {
		ID   string `json:"id"`
		DANE string `json:"dane"`
	}
	if err := d.C.Get(ctx, "MtaTlsStrategy", ids, []string{"id", "dane"}, &ss); err != nil {
		return err
	}
	upd := map[string]map[string]any{}
	for _, s := range ss {
		// "require" is never set by Portcullis; leave an operator's choice.
		if s.DANE != want && s.DANE != "require" {
			upd[s.ID] = map[string]any{"dane": want}
		}
	}
	if len(upd) == 0 {
		return nil
	}
	r, err := d.C.Set(ctx, "MtaTlsStrategy", nil, upd, nil)
	if err == nil {
		err = r.Failed()
	}
	if err != nil {
		return err
	}
	if d.Logf != nil {
		b, _ := json.Marshal(want)
		d.Logf("checks: outbound DANE set to %s on %d strategies", b, len(upd))
	}
	return d.C.Action(ctx, "ReloadSettings")
}

// askRetry: a cold resolver can take longer than one query's timeout on
// a broken chain; it caches the verdict, so ask up to three times.
func askRetry(ctx context.Context, d Deps, name string, qtype uint16) (*dns.Msg, error) {
	var err error
	for i := 0; i < 3; i++ {
		var m *dns.Msg
		if m, err = d.DNS(ctx, d.Cfg.LocalResolver, name, qtype, true); err == nil {
			return m, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, err
}
