package checks

import (
	"context"
	"encoding/json"

	"github.com/miekg/dns"
)

// DANE probe names: a signed name (AD expected) and a deliberately broken
// one (SERVFAIL expected).
const (
	DANESigned = "dnssec.works"
	DANEBroken = "fail01.dnssec.works"
)

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

// dane: mail-resolver validates DNSSEC (a signed name answers with AD, a
// broken one with SERVFAIL). When it can't, outbound DANE is switched off
// (every MtaTlsStrategy dane: disable; MTA-STS and STARTTLS still apply),
// and on again once the check passes. A failed probe changes nothing.
func dane(ctx context.Context, d Deps) Check {
	c := Check{ID: "dane", Severity: OK, Detail: "mail-resolver validates DNSSEC: outbound DANE is on"}
	good, err := askRetry(ctx, d, DANESigned)
	if err != nil {
		c.Severity, c.Detail = Info, "mail-resolver couldn't be asked: DANE left as it was"
		return c
	}
	broken, err := askRetry(ctx, d, DANEBroken)
	if err != nil {
		c.Severity, c.Detail = Info, "mail-resolver couldn't be asked: DANE left as it was"
		return c
	}
	validates := good.Rcode == dns.RcodeSuccess && good.AuthenticatedData && broken.Rcode == dns.RcodeServerFailure
	want := "optional"
	if !validates {
		want = "disable"
		c.Severity = Info
		c.Detail = "DANE is off: the resolver can't validate DNSSEC"
		c.Steps = []string{"mail-resolver needs to reach the root servers over UDP and TCP port 53; check the host's firewall."}
	}
	if err := setDANE(ctx, d, want); err != nil {
		c.Severity = Warning
		c.Detail += "; switching DANE failed: " + err.Error()
	}
	return c
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
func askRetry(ctx context.Context, d Deps, name string) (*dns.Msg, error) {
	var err error
	for i := 0; i < 3; i++ {
		var m *dns.Msg
		if m, err = d.DNS(ctx, d.Cfg.LocalResolver, name, dns.TypeA, true); err == nil {
			return m, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, err
}
