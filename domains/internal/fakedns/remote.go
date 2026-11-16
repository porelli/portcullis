package fakedns

// One fake zone for several processes (CI only, the testprovider build):
// the domains service serves its zone's provider calls over HTTP
// (APIHandler, DOMAINS_FAKEDNS_API_ADDR) and the one-shots of the same
// image (dns-tool, mail-cert) talk to it through Remote
// (DOMAINS_FAKEDNS_REMOTE), so every record they write is in the zone
// the domains service answers DNS from. Without it each one-shot writes
// into its own in-memory zone, gone when it exits.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/libdns/libdns"
	"github.com/miekg/dns"
)

// wireRR is a record on the wire (TTL in seconds).
type wireRR struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  int64  `json:"ttl"`
	Data string `json:"data"`
}

type apiReq struct {
	Op      string   `json:"op"` // get | append | set | delete
	Zone    string   `json:"zone"`
	Token   string   `json:"token"`
	Records []wireRR `json:"records"`
}

type apiResp struct {
	Records []wireRR `json:"records"`
	Error   string   `json:"error,omitempty"`
	Auth    bool     `json:"auth,omitempty"` // the token was refused
}

func toWire(recs []libdns.Record) []wireRR {
	out := make([]wireRR, 0, len(recs))
	for _, r := range recs {
		rr := r.RR()
		out = append(out, wireRR{Name: rr.Name, Type: rr.Type, TTL: int64(rr.TTL / time.Second), Data: rr.Data})
	}
	return out
}

func fromWire(ws []wireRR) []libdns.Record {
	out := make([]libdns.Record, 0, len(ws))
	for _, w := range ws {
		out = append(out, parsed(libdns.RR{Name: w.Name, Type: w.Type, TTL: time.Duration(w.TTL) * time.Second, Data: w.Data}))
	}
	return out
}

// APIHandler serves z's provider calls: POST / with an apiReq. accept
// judges the caller's token as the local provider would.
func APIHandler(z *Zone, accept func(token string) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req apiReq
		d := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
		d.DisallowUnknownFields()
		if err := d.Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		p := &Provider{Zone: z, Token: req.Token, Accept: accept}
		recs := fromWire(req.Records)
		var (
			out []libdns.Record
			err error
		)
		ctx := r.Context()
		switch req.Op {
		case "get":
			out, err = p.GetRecords(ctx, req.Zone)
		case "append":
			out, err = p.AppendRecords(ctx, req.Zone, recs)
		case "set":
			out, err = p.SetRecords(ctx, req.Zone, recs)
		case "delete":
			out, err = p.DeleteRecords(ctx, req.Zone, recs)
		default:
			http.Error(w, "unknown op", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		resp := apiResp{Records: toWire(out)}
		if err != nil {
			// The token is never sent back (the local provider's error
			// quotes it on purpose: the service must redact it).
			resp = apiResp{Error: "the fake provider refused the call", Auth: errors.Is(err, ErrAuth)}
			if !resp.Auth {
				resp.Error = err.Error()
			}
		}
		json.NewEncoder(w).Encode(resp)
	})
}

// Remote is a libdns provider on another process's zone (APIHandler at
// URL).
type Remote struct {
	URL    string
	Token  string
	Client *http.Client
}

func (p *Remote) call(ctx context.Context, op, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	body, _ := json.Marshal(apiReq{Op: op, Zone: zone, Token: p.Token, Records: toWire(recs)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	c := p.Client
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	res, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("the fake zone at %s: %w", p.URL, err)
	}
	defer res.Body.Close()
	var out apiResp
	if res.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(&out) != nil {
		return nil, fmt.Errorf("the fake zone at %s: HTTP %d", p.URL, res.StatusCode)
	}
	if out.Auth {
		return nil, fmt.Errorf("%w: token %q was rejected by the fake provider", ErrAuth, p.Token)
	}
	if out.Error != "" {
		return nil, errors.New(out.Error)
	}
	return fromWire(out.Records), nil
}

// GetRecords lists every record of the zone.
func (p *Remote) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	return p.call(ctx, "get", zone, nil)
}

// AppendRecords adds records.
func (p *Remote) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return p.call(ctx, "append", zone, recs)
}

// SetRecords makes each input (name, type) RRset exactly the input.
func (p *Remote) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return p.call(ctx, "set", zone, recs)
}

// DeleteRecords removes matching records.
func (p *Remote) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return p.call(ctx, "delete", zone, recs)
}

// FindZone is the local provider's (the name itself, minus the ACME label).
func (p *Remote) FindZone(fqdn string) (string, error) {
	return dns.Fqdn(strings.TrimPrefix(fqdn, "_acme-challenge.")), nil
}

// SkipPropagationCheck: as the local provider.
func (p *Remote) SkipPropagationCheck() bool { return true }
