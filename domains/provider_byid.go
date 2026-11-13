package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"

	"github.com/portcullis/domains/internal/dnsplan"
)

// Exact deletes for the libdns packages whose DeleteRecords ignores the
// record's data (final review C1, pinned versions read):
//   - libdns/porkbun v1.1.0 calls /dns/deleteByNameType: EVERY record with
//     the name and type goes (all CAA at <d>, every A, every TXT);
//   - libdns/hetzner v1.0.0 deletes the FIRST record with the name and
//     type it lists (findRecordID), whatever its data.
// Both APIs list records with their IDs and delete one by ID, so
// byIDDelete keeps the library for get / append / set and deletes exactly
// the matching records by ID. (cloudflare v0.2.2 matches content, route53
// v1.6.2 and hetzner/v2 v2.0.1 remove values from the RRset, DigitalOcean
// is our own doProvider: they need nothing.)

// idRecord is a live record with its provider ID; rr.Name is relative to
// the zone ("@" at the apex).
type idRecord struct {
	id string
	rr libdns.RR
}

// recordAPI lists a zone's records with their IDs and deletes one by ID.
type recordAPI interface {
	listIDs(ctx context.Context, zone string) ([]idRecord, error)
	deleteID(ctx context.Context, zone, id string) error
}

type byIDDelete struct {
	dnsProvider
	api recordAPI
}

func newByIDDelete(lib dnsProvider, api recordAPI) dnsProvider {
	return byIDDelete{dnsProvider: lib, api: api}
}

// matchKey compares data on parsed fields (dnsplan.DataKey, a CAA value
// canonical: libdns/porkbun reads it quoted); TXT values some APIs return
// quoted compare unquoted.
func matchKey(typ, data string) string {
	if typ == "TXT" && len(data) >= 2 && strings.HasPrefix(data, `"`) && strings.HasSuffix(data, `"`) {
		if u, err := strconv.Unquote(data); err == nil {
			data = u
		}
	}
	return dnsplan.DataKey(typ, data)
}

// DeleteRecords deletes exactly the live records matching each input by
// name, type, data (parsed) and TTL when set. An input without a type or
// data is refused (fail closed: it would match a whole RRset); an input
// matching nothing is skipped (libdns semantics).
func (p byIDDelete) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	for _, r := range recs {
		if w := r.RR(); w.Type == "" || w.Data == "" {
			return nil, fmt.Errorf("refusing to delete every record at %s without a type and value", w.Name)
		}
	}
	live, err := p.api.listIDs(ctx, zone)
	if err != nil {
		return nil, err
	}
	// The listing enters our model canonical (as GetRecords' records do in
	// dnsplan); the delete itself goes by the provider's record ID.
	for i := range live {
		live[i].rr = dnsplan.CanonicalRR(live[i].rr)
	}
	rel := func(n string) string { return libdns.RelativeName(libdns.AbsoluteName(n, zone), zone) }
	var out []libdns.Record
	done := map[string]bool{}
	for _, r := range recs {
		w := r.RR()
		for _, l := range live {
			if done[l.id] || !sameName(rel(l.rr.Name), rel(w.Name)) || l.rr.Type != w.Type ||
				(w.TTL != 0 && w.TTL != l.rr.TTL) || matchKey(l.rr.Type, l.rr.Data) != matchKey(w.Type, w.Data) {
				continue
			}
			if err := p.api.deleteID(ctx, zone, l.id); err != nil {
				return out, fmt.Errorf("deleting %s %s: %w", l.rr.Type, l.rr.Name, err)
			}
			done[l.id] = true
			out = append(out, parsedRec(l.rr))
		}
	}
	return out, nil
}

func parsedRec(rr libdns.RR) libdns.Record {
	if r, err := rr.Parse(); err == nil {
		return r
	}
	return rr
}

// maxAPIBody bounds an API answer read.
const maxAPIBody = 8 << 20

// flexString decodes a JSON string or number (porkbun sends IDs and TTLs
// as strings, but numbers are accepted too).
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*f = flexString(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*f = flexString(n.String())
	return nil
}

// apiDo runs one request and decodes the 2xx JSON answer into out; the
// error names the status only (redacting cleans it anyway).
func apiDo(hc *http.Client, req *http.Request, out any) error {
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIBody))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s %s: HTTP %d", req.Method, req.URL.Path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}

// porkbunAPI: retrieve (records with "id") and delete by ID.
type porkbunAPI struct {
	base, key, secret string
	hc                *http.Client
}

const porkbunBase = "https://api.porkbun.com/api/json/v3"

func newPorkbunAPI(key, secret string) porkbunAPI {
	return porkbunAPI{base: porkbunBase, key: key, secret: secret, hc: &http.Client{Timeout: providerTimeout}}
}

func (a porkbunAPI) post(ctx context.Context, path string, out any) error {
	body, err := json.Marshal(map[string]string{"apikey": a.key, "secretapikey": a.secret})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	var st struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	raw := json.RawMessage{}
	if err := apiDo(a.hc, req, &raw); err != nil {
		return fmt.Errorf("porkbun: %w", err)
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return fmt.Errorf("porkbun: %s: %w", path, err)
	}
	if st.Status != "SUCCESS" {
		return fmt.Errorf("porkbun: %s: status %q %s", path, st.Status, st.Message)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func porkbunDomain(zone string) string { return url.PathEscape(strings.TrimSuffix(zone, ".")) }

func (a porkbunAPI) listIDs(ctx context.Context, zone string) ([]idRecord, error) {
	var res struct {
		Records []struct {
			ID      flexString `json:"id"`
			Name    string     `json:"name"`
			Type    string     `json:"type"`
			Content string     `json:"content"`
			TTL     flexString `json:"ttl"`
			Prio    flexString `json:"prio"`
		} `json:"records"`
	}
	if err := a.post(ctx, "/dns/retrieve/"+porkbunDomain(zone), &res); err != nil {
		return nil, err
	}
	out := make([]idRecord, 0, len(res.Records))
	for _, r := range res.Records {
		if r.ID == "" {
			return nil, errors.New("porkbun: a record without an id")
		}
		data := r.Content
		if (r.Type == "MX" || r.Type == "SRV") && r.Prio != "" {
			data = string(r.Prio) + " " + r.Content
		}
		ttl, _ := strconv.Atoi(string(r.TTL))
		out = append(out, idRecord{id: string(r.ID), rr: libdns.RR{Name: libdns.RelativeName(r.Name+".", zone), Type: r.Type,
			TTL: time.Duration(ttl) * time.Second, Data: data}})
	}
	return out, nil
}

func (a porkbunAPI) deleteID(ctx context.Context, zone, id string) error {
	return a.post(ctx, "/dns/delete/"+porkbunDomain(zone)+"/"+url.PathEscape(id), nil)
}

// hetznerAPI: the legacy DNS API's records (with IDs) and DELETE by ID.
type hetznerAPI struct {
	base, token string
	hc          *http.Client
}

const hetznerBase = "https://dns.hetzner.com/api/v1"

func newHetznerAPI(token string) hetznerAPI {
	return hetznerAPI{base: hetznerBase, token: token, hc: &http.Client{Timeout: providerTimeout}}
}

func (a hetznerAPI) do(ctx context.Context, method, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Auth-API-Token", a.token)
	if err := apiDo(a.hc, req, out); err != nil {
		return fmt.Errorf("hetzner: %w", err)
	}
	return nil
}

func (a hetznerAPI) listIDs(ctx context.Context, zone string) ([]idRecord, error) {
	name := strings.TrimSuffix(zone, ".")
	var zs struct {
		Zones []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"zones"`
	}
	if err := a.do(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(name), &zs); err != nil {
		return nil, err
	}
	if len(zs.Zones) != 1 || zs.Zones[0].ID == "" {
		return nil, fmt.Errorf("hetzner: %d zones named %s", len(zs.Zones), name)
	}
	if got := strings.TrimSuffix(strings.ToLower(zs.Zones[0].Name), "."); got != strings.ToLower(name) {
		return nil, fmt.Errorf("hetzner: asked for the zone %s, got %s", name, got)
	}
	var rs struct {
		Records []struct {
			ID    string `json:"id"`
			Type  string `json:"type"`
			Name  string `json:"name"`
			Value string `json:"value"`
			TTL   int    `json:"ttl"`
		} `json:"records"`
	}
	if err := a.do(ctx, http.MethodGet, "/records?zone_id="+url.QueryEscape(zs.Zones[0].ID), &rs); err != nil {
		return nil, err
	}
	out := make([]idRecord, 0, len(rs.Records))
	for _, r := range rs.Records {
		if r.ID == "" {
			return nil, errors.New("hetzner: a record without an id")
		}
		out = append(out, idRecord{id: r.ID, rr: libdns.RR{Name: r.Name, Type: r.Type, TTL: time.Duration(r.TTL) * time.Second, Data: r.Value}})
	}
	return out, nil
}

func (a hetznerAPI) deleteID(ctx context.Context, _ string, id string) error {
	return a.do(ctx, http.MethodDelete, "/records/"+url.PathEscape(id), nil)
}
