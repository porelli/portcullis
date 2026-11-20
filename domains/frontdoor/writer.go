package frontdoor

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// Provider is what the front door needs from the domains service's
// providers (records.go's dnsProvider behind its redacting wrapper): read
// the zone, append, and delete exact values (porkbun and hetzner by
// record ID, provider_byid.go).
type Provider interface {
	libdns.RecordGetter
	libdns.RecordAppender
	libdns.RecordDeleter
}

// ErrStandingBy: without the Lease nothing is written (§20.5).
var ErrStandingBy = errors.New("the front door is standing by: another front door holds the Lease")

// Writer writes the main domain's address set: append first, then delete
// only the exact stale value (by record ID where the provider needs it),
// never leaving a name without an address.
type Writer struct {
	// Domain is the main domain <d> (no trailing dot); Zone the DNS zone
	// holding it (FQDN, trailing dot).
	Domain, Zone string
	P            Provider
	TTL          time.Duration
	// Leading is the write fence: false refuses every write.
	Leading func() bool
}

// Names are the address set's names.
func (w *Writer) Names() []string { return []string{w.Domain, "*." + w.Domain} }

// Allowed reports whether the front door may write a record of type typ
// at name (§20.8): A / AAAA / CAA at <d> and *.<d>, TXT at
// _acme-challenge.<d>; nothing else.
func (w *Writer) Allowed(name, typ string) error {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	d := strings.ToLower(w.Domain)
	switch {
	case d != "" && (n == d || n == "*."+d) && (typ == "A" || typ == "AAAA" || typ == "CAA"):
		return nil
	case d != "" && n == "_acme-challenge."+d && typ == "TXT":
		return nil
	}
	return fmt.Errorf("refusing to write %s %s: the front door writes only the main domain's address set, its CAA and _acme-challenge.%s", typ, name, w.Domain)
}

func (w *Writer) rel(name string) string {
	return libdns.RelativeName(strings.TrimSuffix(name, ".")+".", w.Zone)
}

func (w *Writer) abs(rel string) string {
	return strings.ToLower(strings.TrimSuffix(libdns.AbsoluteName(rel, w.Zone), "."))
}

// Published reads the address set of each name (A and AAAA values)
// from the provider.
func (w *Writer) Published(ctx context.Context) (map[string][]string, error) {
	recs, err := w.P.GetRecords(ctx, w.Zone)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, n := range w.Names() {
		out[n] = []string{}
	}
	for _, r := range recs {
		rr := r.RR()
		if rr.Type != "A" && rr.Type != "AAAA" {
			continue
		}
		name := w.abs(rr.Name)
		if _, ok := out[name]; !ok {
			continue
		}
		ip, err := netip.ParseAddr(strings.TrimSpace(rr.Data))
		if err != nil {
			continue
		}
		out[name] = append(out[name], ip.String())
	}
	for n := range out {
		sort.Strings(out[n])
	}
	return out, nil
}

// Apply writes one change: an add appends the value (nothing when it is
// already there); a remove re-reads the name's set first and refuses to
// delete the last address, then deletes exactly that value (no TTL: the
// provider may store another, Porkbun 600 s). Every check comes before
// the provider is called.
func (w *Writer) Apply(ctx context.Context, c Change) error {
	if w.Leading == nil || !w.Leading() {
		return ErrStandingBy
	}
	typ := AddrType(c.Value)
	if typ == "" || (c.Type != "" && c.Type != typ) {
		return fmt.Errorf("refusing %s %s %q: not an address of type %s", c.Op, c.Name, c.Value, c.Type)
	}
	if err := w.Allowed(c.Name, typ); err != nil {
		return err
	}
	if c.Op != "add" && c.Op != "remove" {
		return fmt.Errorf("refusing the change %q", c.Op)
	}
	ip := netip.MustParseAddr(c.Value)
	name := strings.ToLower(strings.TrimSuffix(c.Name, "."))
	pub, err := w.Published(ctx)
	if err != nil {
		return fmt.Errorf("reading %s before the change: %w", name, err)
	}
	have := false
	for _, a := range pub[name] {
		have = have || a == ip.String()
	}
	switch c.Op {
	case "add":
		if have {
			return nil
		}
		if !w.Leading() {
			return ErrStandingBy
		}
		_, err := w.P.AppendRecords(ctx, w.Zone, []libdns.Record{libdns.Address{Name: w.rel(name), TTL: w.TTL, IP: ip}})
		if err != nil {
			return fmt.Errorf("adding %s to %s: %w", ip, name, err)
		}
		return nil
	default:
		if !have {
			return nil
		}
		if len(pub[name]) < 2 {
			return fmt.Errorf("refusing to remove %s: it is the last address of %s", ip, name)
		}
		if !w.Leading() {
			return ErrStandingBy
		}
		if _, err := w.P.DeleteRecords(ctx, w.Zone, []libdns.Record{libdns.Address{Name: w.rel(name), IP: ip}}); err != nil {
			return fmt.Errorf("removing %s from %s: %w", ip, name, err)
		}
		return nil
	}
}
