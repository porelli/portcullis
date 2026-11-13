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

	"github.com/portcullis/domains/internal/dnssec"
)

// cloudflareDNSSEC reads and turns on a Cloudflare zone's DNSSEC signing
// through its API (the same token as the records). It never turns
// signing off: no request it sends carries "disabled".
type cloudflareDNSSEC struct {
	token string
	base  string // default https://api.cloudflare.com/client/v4
	hc    *http.Client
}

func newCloudflareDNSSEC(c map[string]string) (dnssec.StatusReader, error) {
	return &cloudflareDNSSEC{token: c["api_token"], base: "https://api.cloudflare.com/client/v4", hc: &http.Client{Timeout: providerTimeout}}, nil
}

// cfNumber decodes a number Cloudflare sends as a JSON number or string.
type cfNumber uint64

func (n *cfNumber) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*n = 0
		return nil
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return err
	}
	*n = cfNumber(v)
	return nil
}

type cfEnvelope struct {
	Success bool            `json:"success"`
	Errors  []cfError       `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// errCloudflareDNSSECPermission: the token lacks the DNSSEC permission.
var errCloudflareDNSSECPermission = errors.New("the Cloudflare token needs the Zone › DNS Settings › Edit permission to turn on DNSSEC")

func (c *cloudflareDNSSEC) call(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("cloudflare %s %s: %w", method, path, err)
	}
	var env cfEnvelope
	_ = json.Unmarshal(raw, &env)
	if resp.StatusCode == http.StatusForbidden {
		return errCloudflareDNSSECPermission
	}
	if resp.StatusCode/100 != 2 || !env.Success {
		msgs := make([]string, 0, len(env.Errors))
		for _, e := range env.Errors {
			msgs = append(msgs, fmt.Sprintf("%d %s", e.Code, e.Message))
		}
		return fmt.Errorf("cloudflare %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.Join(msgs, "; "))
	}
	if out != nil {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return fmt.Errorf("cloudflare %s %s: %w", method, path, err)
		}
	}
	return nil
}

func (c *cloudflareDNSSEC) zoneID(ctx context.Context, zone string) (string, error) {
	name := strings.TrimSuffix(strings.ToLower(zone), ".")
	var zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := c.call(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(name), nil, &zones); err != nil {
		return "", err
	}
	for _, z := range zones {
		if strings.EqualFold(z.Name, name) {
			return z.ID, nil
		}
	}
	return "", fmt.Errorf("cloudflare: no zone %s for this token", name)
}

type cfDNSSEC struct {
	Status     string   `json:"status"`
	KeyTag     cfNumber `json:"key_tag"`
	Algorithm  cfNumber `json:"algorithm"`
	DigestType cfNumber `json:"digest_type"`
	Digest     string   `json:"digest"`
}

// DNSSECStatus: Cloudflare's status (active, pending, disabled, …) and
// the DS to publish at the registrar.
func (c *cloudflareDNSSEC) DNSSECStatus(ctx context.Context, zone string) (string, []dnssec.DS, error) {
	id, err := c.zoneID(ctx, zone)
	if err != nil {
		return "", nil, err
	}
	var st cfDNSSEC
	if err := c.call(ctx, http.MethodGet, "/zones/"+url.PathEscape(id)+"/dnssec", nil, &st); err != nil {
		return "", nil, err
	}
	var ds []dnssec.DS
	if st.Digest != "" {
		ds = []dnssec.DS{{KeyTag: uint16(st.KeyTag), Algorithm: uint8(st.Algorithm), DigestType: uint8(st.DigestType), Digest: strings.ToUpper(st.Digest)}}
	}
	return st.Status, ds, nil
}

// EnableDNSSEC turns signing on for the whole zone.
func (c *cloudflareDNSSEC) EnableDNSSEC(ctx context.Context, zone string) error {
	id, err := c.zoneID(ctx, zone)
	if err != nil {
		return err
	}
	return c.call(ctx, http.MethodPatch, "/zones/"+url.PathEscape(id)+"/dnssec", map[string]string{"status": "active"}, nil)
}
