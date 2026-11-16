package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// porkbunProvider is Porkbun's DNS API v3 (api.porkbun.com/api/json/v3)
// done by hand. libdns/porkbun v1.1.0 got it wrong for every type the mail
// set needs (test server, 2026-11-16):
//   - create sends the whole RR data as content and never "prio": an MX
//     ("10 host.") or SRV ("0 1 465 host.") is refused with
//     CREATE_ERROR_WE_WERE_UNABLE_TO_CREATE_THE_DNS_RECORD;
//   - its reads drop MX and TLSA ("Unsupported record type") and garble
//     SRV names; CAA values keep their quotes;
//   - its delete removes every record with the name and type.
//
// What Porkbun takes and answers (checked live under
// _pc-test.portcullis.imbu.ca, then deleted): MX and SRV with the priority
// in "prio" and the rest in "content" (MX: the target, a trailing dot kept
// as sent; SRV: "weight port target"; the null MX "." and the null SRV
// "0 0 ." included), TLSA "3 1 1 <hex>", a ~400-byte TXT unsplit, CAA as
// libdns writes it (`0 issue "…"`); "name" is relative to the domain
// ("" at the apex); a TTL under 600 s is raised to 600.
type porkbunProvider struct{ api porkbunAPI }

func newPorkbunProvider(api porkbunAPI) dnsProvider {
	return porkbunProvider{api: api}
}

// porkbunMinTTL: Porkbun refuses (or raises) anything shorter.
const porkbunMinTTL = 600 * time.Second

// GetRecords: every record of the zone, parsed (MX / SRV with their
// priority back in the data, CAA unquoted by libdns' parser); a record
// libdns can't parse comes back as its raw RR.
func (p porkbunProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	live, err := p.api.listIDs(ctx, zone)
	if err != nil {
		return nil, err
	}
	out := make([]libdns.Record, 0, len(live))
	for _, l := range live {
		out = append(out, parsedRec(l.rr))
	}
	return out, nil
}

// porkbunCreate is one /dns/create body (without the keys).
type porkbunCreate struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     string `json:"ttl"`
	Prio    string `json:"prio,omitempty"`
}

// porkbunBody turns a record into Porkbun's create fields.
func porkbunBody(r libdns.Record, zone string) (porkbunCreate, error) {
	rr := r.RR()
	name := libdns.RelativeName(libdns.AbsoluteName(rr.Name, zone), zone)
	if name == "@" {
		name = ""
	}
	ttl := rr.TTL
	if ttl < porkbunMinTTL {
		ttl = porkbunMinTTL
	}
	b := porkbunCreate{Name: name, Type: rr.Type, Content: rr.Data, TTL: strconv.Itoa(int(ttl / time.Second))}
	switch rr.Type {
	case "MX", "SRV":
		prio, rest, ok := strings.Cut(strings.TrimSpace(rr.Data), " ")
		if _, err := strconv.ParseUint(prio, 10, 16); !ok || err != nil || strings.TrimSpace(rest) == "" {
			return porkbunCreate{}, fmt.Errorf("porkbun: %s %s: data %q has no priority first", rr.Type, rr.Name, rr.Data)
		}
		b.Prio, b.Content = prio, strings.TrimSpace(rest)
	}
	if b.Type == "" || b.Content == "" {
		return porkbunCreate{}, fmt.Errorf("porkbun: a record at %s without a type or value", rr.Name)
	}
	return b, nil
}

// AppendRecords creates each record (one /dns/create per record); it
// stops at the first refusal and returns what was created before it.
func (p porkbunProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	var out []libdns.Record
	for _, r := range recs {
		b, err := porkbunBody(r, zone)
		if err != nil {
			return out, err
		}
		if err := p.api.create(ctx, zone, b); err != nil {
			return out, fmt.Errorf("%s %s: %w", b.Type, r.RR().Name, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// DeleteRecords deletes exactly the matching records by ID (byIDDelete).
func (p porkbunProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return byIDDelete{api: p.api}.DeleteRecords(ctx, zone, recs)
}

// SetRecords makes each input (name, type) RRset exactly the input:
// missing records are created first, then the other live ones of that
// RRset are deleted by ID (append-first, as the records step).
func (p porkbunProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	live, err := p.api.listIDs(ctx, zone)
	if err != nil {
		return nil, err
	}
	rel := func(n string) string { return libdns.RelativeName(libdns.AbsoluteName(n, zone), zone) }
	type key struct{ n, t string }
	want := map[key][]libdns.RR{}
	var order []key
	for _, r := range recs {
		rr := r.RR()
		k := key{strings.ToLower(rel(rr.Name)), rr.Type}
		if _, ok := want[k]; !ok {
			order = append(order, k)
		}
		want[k] = append(want[k], rr)
	}
	var out []libdns.Record
	for _, k := range order {
		have := map[string]bool{}
		var stale []idRecord
		for _, l := range live {
			if !sameName(rel(l.rr.Name), k.n) || l.rr.Type != k.t {
				continue
			}
			keep := false
			for _, w := range want[k] {
				if matchKey(w.Type, w.Data) == matchKey(l.rr.Type, l.rr.Data) {
					keep = true
				}
			}
			if keep {
				have[matchKey(l.rr.Type, l.rr.Data)] = true
			} else {
				stale = append(stale, l)
			}
		}
		for _, w := range want[k] {
			if have[matchKey(w.Type, w.Data)] {
				out = append(out, parsedRec(w))
				continue
			}
			b, err := porkbunBody(w, zone)
			if err != nil {
				return out, err
			}
			if err := p.api.create(ctx, zone, b); err != nil {
				return out, fmt.Errorf("%s %s: %w", b.Type, w.Name, err)
			}
			have[matchKey(w.Type, w.Data)] = true
			out = append(out, parsedRec(w))
		}
		for _, s := range stale {
			if err := p.api.deleteID(ctx, zone, s.id); err != nil {
				return out, fmt.Errorf("deleting %s %s: %w", s.rr.Type, s.rr.Name, err)
			}
		}
	}
	return out, nil
}

// create is one /dns/create call.
func (a porkbunAPI) create(ctx context.Context, zone string, b porkbunCreate) error {
	var res struct {
		ID flexString `json:"id"`
	}
	if err := a.postBody(ctx, "/dns/create/"+porkbunDomain(zone), b, &res); err != nil {
		return err
	}
	if res.ID == "" {
		return errors.New("porkbun: /dns/create answered no id")
	}
	return nil
}
