package main

import (
	"context"
	"fmt"
	"net/http"

	"strings"
	"time"

	"github.com/digitalocean/godo"
	"github.com/libdns/libdns"
)

// doProvider is the DigitalOcean provider, on godo (DigitalOcean's own
// client, which libdns/digitalocean wraps). libdns/digitalocean can't be
// used as is: it sends only "data" (DigitalOcean needs flags + tag for
// CAA and priority for MX), and its SetRecords / DeleteRecords need the
// provider's record IDs, which libdns callers don't have. Record
// conversion follows libdns RR data (zone-file form).
type doProvider struct {
	client *godo.Client
}

func newDOProvider(token string) *doProvider {
	c := godo.NewFromToken(token)
	c.HTTPClient.Timeout = providerTimeout
	return &doProvider{client: c}
}

// newDOProviderAt is newDOProvider against a test API.
func newDOProviderAt(hc *http.Client, base string) (*doProvider, error) {
	c, err := godo.New(hc, godo.SetBaseURL(base))
	if err != nil {
		return nil, err
	}
	return &doProvider{client: c}, nil
}

func doDomain(zone string) string { return strings.TrimSuffix(zone, ".") }

// doRec is a live record with its ID.
type doRec struct {
	id int
	rr libdns.RR
}

func fromDO(e godo.DomainRecord) libdns.RR {
	rr := libdns.RR{Name: e.Name, Type: e.Type, TTL: time.Duration(e.TTL) * time.Second, Data: e.Data}
	switch e.Type {
	case "CAA":
		rr.Data = libdns.CAA{Flags: uint8(e.Flags), Tag: e.Tag, Value: e.Data}.RR().Data
	case "MX":
		rr.Data = fmt.Sprintf("%d %s", e.Priority, e.Data)
	case "SRV":
		rr.Data = fmt.Sprintf("%d %d %d %s", e.Priority, e.Weight, e.Port, e.Data)
	}
	return rr
}

func toDO(r libdns.Record) (godo.DomainRecordEditRequest, error) {
	rr := r.RR()
	req := godo.DomainRecordEditRequest{Type: rr.Type, Name: rr.Name, Data: rr.Data, TTL: int(rr.TTL / time.Second)}
	if req.TTL < 30 {
		req.TTL = 1800 // DigitalOcean's minimum is 30; 0 = its default
	}
	switch rr.Type {
	case "CAA", "MX":
		p, err := rr.Parse()
		if err != nil {
			return req, fmt.Errorf("digitalocean: %s record %s: %w", rr.Type, rr.Name, err)
		}
		switch v := p.(type) {
		case libdns.CAA:
			req.Flags, req.Tag, req.Data = int(v.Flags), v.Tag, v.Value
		case libdns.MX:
			req.Priority, req.Data = int(v.Preference), v.Target
		}
	}
	return req, nil
}

func (p *doProvider) list(ctx context.Context, zone string) ([]doRec, error) {
	var out []doRec
	opt := &godo.ListOptions{PerPage: 200}
	for {
		recs, resp, err := p.client.Domains.Records(ctx, doDomain(zone), opt)
		if err != nil {
			return nil, fmt.Errorf("digitalocean: listing the records of %s: %w", doDomain(zone), err)
		}
		for _, e := range recs {
			out = append(out, doRec{id: e.ID, rr: fromDO(e)})
		}
		if resp == nil || resp.Links == nil || resp.Links.IsLastPage() {
			return out, nil
		}
		page, err := resp.Links.CurrentPage()
		if err != nil {
			return nil, err
		}
		opt.Page = page + 1
	}
}

func parsedRR(rr libdns.RR) libdns.Record {
	if r, err := rr.Parse(); err == nil {
		return r
	}
	return rr
}

// GetRecords lists every record of the zone.
func (p *doProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	live, err := p.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	out := make([]libdns.Record, 0, len(live))
	for _, l := range live {
		out = append(out, parsedRR(l.rr))
	}
	return out, nil
}

// AppendRecords creates records.
func (p *doProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	var out []libdns.Record
	for _, r := range recs {
		req, err := toDO(r)
		if err != nil {
			return out, err
		}
		if _, _, err := p.client.Domains.CreateRecord(ctx, doDomain(zone), &req); err != nil {
			return out, fmt.Errorf("digitalocean: creating %s %s: %w", req.Type, req.Name, err)
		}
		out = append(out, r)
	}
	return out, nil
}

func sameName(a, b string) bool {
	norm := func(s string) string {
		s = strings.ToLower(strings.TrimSuffix(s, "."))
		if s == "" {
			return "@"
		}
		return s
	}
	return norm(a) == norm(b)
}

// SetRecords makes every input (name, type) RRset exactly the input.
func (p *doProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	live, err := p.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	type key struct{ n, t string }
	want := map[key][]libdns.RR{}
	var order []key
	for _, r := range recs {
		rr := r.RR()
		k := key{strings.ToLower(rr.Name), rr.Type}
		if _, ok := want[k]; !ok {
			order = append(order, k)
		}
		want[k] = append(want[k], rr)
	}
	var out []libdns.Record
	for _, k := range order {
		var have []doRec
		for _, l := range live {
			if sameName(l.rr.Name, k.n) && l.rr.Type == k.t {
				have = append(have, l)
			}
		}
		// Create the missing records first, then delete the stale ones:
		// never a moment without the new entries (a CAA pin).
		for _, w := range want[k] {
			exists := false
			for _, h := range have {
				if w.Data == h.rr.Data && w.TTL == h.rr.TTL {
					exists = true
				}
			}
			if !exists {
				if _, err := p.AppendRecords(ctx, zone, []libdns.Record{w}); err != nil {
					return out, err
				}
			}
			out = append(out, parsedRR(w))
		}
		for _, h := range have {
			keep := false
			for _, w := range want[k] {
				if w.Data == h.rr.Data && w.TTL == h.rr.TTL {
					keep = true
				}
			}
			if !keep {
				if _, err := p.client.Domains.DeleteRecord(ctx, doDomain(zone), h.id); err != nil {
					return out, fmt.Errorf("digitalocean: replacing %s %s: %w", k.t, k.n, err)
				}
			}
		}
	}
	return out, nil
}

// DeleteRecords removes matching records (empty type / TTL / data match
// anything, as libdns specifies).
func (p *doProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	live, err := p.list(ctx, zone)
	if err != nil {
		return nil, err
	}
	var out []libdns.Record
	done := map[int]bool{}
	for _, r := range recs {
		w := r.RR()
		for _, l := range live {
			if done[l.id] || !sameName(l.rr.Name, w.Name) || (w.Type != "" && w.Type != l.rr.Type) ||
				(w.TTL != 0 && w.TTL != l.rr.TTL) || (w.Data != "" && w.Data != l.rr.Data) {
				continue
			}
			if _, err := p.client.Domains.DeleteRecord(ctx, doDomain(zone), l.id); err != nil {
				return out, fmt.Errorf("digitalocean: deleting %s %s: %w", l.rr.Type, l.rr.Name, err)
			}
			done[l.id] = true
			out = append(out, parsedRR(l.rr))
		}
	}
	return out, nil
}
