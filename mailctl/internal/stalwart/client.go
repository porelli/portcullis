// Package stalwart is mailctl's thin JMAP envelope for Stalwart's
// management objects (`x:<Object>/get|set|query`, plan ruling M12: no
// maintained Go client exists for them). One method call per request,
// `using` = JMAP core + urn:stalwart:jmap. Errors never carry a secret:
// request bodies (which may hold passwords or keys) are never echoed.
package stalwart

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"
)

// Using is every request's capability list (Task 2: x: methods work with
// core alone, both are sent).
var Using = []string{"urn:ietf:params:jmap:core", "urn:stalwart:jmap"}

// Auth authenticates a request: the API key (Bearer) or the recovery
// admin (Basic).
type Auth interface{ apply(*http.Request) }

type bearer string

func (b bearer) apply(r *http.Request) { r.Header.Set("Authorization", "Bearer "+string(b)) }

type basic struct{ user, pass string }

func (b basic) apply(r *http.Request) { r.SetBasicAuth(b.user, b.pass) }

// Bearer authenticates with Stalwart's API key.
func Bearer(apiKey string) Auth { return bearer(apiKey) }

// Basic authenticates with a user and password (the recovery admin).
func Basic(user, pass string) Auth { return basic{user, pass} }

// Client talks to the management listener.
type Client struct {
	url  string
	auth Auth
	hc   *http.Client
}

// New returns a client for the management listener at url (no trailing /jmap).
func New(url string, auth Auth) *Client {
	return &Client{url: url, auth: auth, hc: &http.Client{
		Timeout: 60 * time.Second,
		// The listener never redirects; following one could send the
		// credentials elsewhere.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// MethodError is a method-level JMAP error (`["error", {type, description}, id]`).
type MethodError struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

func (e *MethodError) Error() string {
	if e.Description == "" {
		return "stalwart: " + e.Type
	}
	return "stalwart: " + e.Type + ": " + e.Description
}

// HTTPError is a non-200 answer (401 bad credentials, 404 refused by the
// access rule, ...). The body is never kept.
type HTTPError struct{ Status int }

func (e *HTTPError) Error() string { return fmt.Sprintf("stalwart: HTTP %d", e.Status) }

// IsUnauthorized reports a 401 (credentials refused).
func IsUnauthorized(err error) bool {
	var h *HTTPError
	return errors.As(err, &h) && h.Status == http.StatusUnauthorized
}

type request struct {
	Using       []string `json:"using"`
	MethodCalls [][3]any `json:"methodCalls"`
}

type response struct {
	MethodResponses []json.RawMessage `json:"methodResponses"`
}

// maxResponse bounds an answer (a full MemoryLookupKey list is ~0.5 MB).
const maxResponse = 64 << 20

// Call sends one method call and decodes its arguments into out (nil =
// discard). A `["error", …]` answer is a *MethodError.
func (c *Client) Call(ctx context.Context, method string, args any, out any) error {
	if args == nil {
		args = map[string]any{}
	}
	body, err := json.Marshal(request{Using: Using, MethodCalls: [][3]any{{method, args, "0"}}})
	if err != nil {
		return fmt.Errorf("stalwart: encoding %s: %w", method, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/jmap", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("stalwart: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	c.auth.apply(req)
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("stalwart: %s: %w", method, errors.Unwrap(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return &HTTPError{Status: resp.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return fmt.Errorf("stalwart: reading %s: %w", method, err)
	}
	if len(raw) > maxResponse {
		return fmt.Errorf("stalwart: %s: answer larger than %d bytes", method, maxResponse)
	}
	var r response
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("stalwart: %s: not a JMAP response", method)
	}
	if len(r.MethodResponses) != 1 {
		return fmt.Errorf("stalwart: %s: %d method responses, want 1", method, len(r.MethodResponses))
	}
	var inv []json.RawMessage
	if err := json.Unmarshal(r.MethodResponses[0], &inv); err != nil || len(inv) != 3 {
		return fmt.Errorf("stalwart: %s: malformed invocation", method)
	}
	var name string
	if err := json.Unmarshal(inv[0], &name); err != nil {
		return fmt.Errorf("stalwart: %s: malformed invocation", method)
	}
	if name == "error" {
		me := &MethodError{}
		if err := json.Unmarshal(inv[1], me); err != nil || me.Type == "" {
			return fmt.Errorf("stalwart: %s: malformed error", method)
		}
		return me
	}
	if name != method {
		return fmt.Errorf("stalwart: asked %s, got %s", method, name)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(inv[1], out); err != nil {
		return fmt.Errorf("stalwart: decoding %s: %w", method, err)
	}
	return nil
}

// SetError is one refused create / update / destroy.
type SetError struct {
	Type        string   `json:"type"`
	Description string   `json:"description,omitempty"`
	Properties  []string `json:"properties,omitempty"`
}

func (e SetError) Error() string {
	s := e.Type
	if e.Description != "" {
		s += ": " + e.Description
	}
	return s
}

// SetResult is a /set answer. Created maps the request's creation ids to
// the server's answer (at least `id`; an AppPassword also has `secret`).
type SetResult struct {
	Created      map[string]map[string]json.RawMessage `json:"created"`
	Updated      map[string]json.RawMessage            `json:"updated"`
	Destroyed    []string                              `json:"destroyed"`
	NotCreated   map[string]SetError                   `json:"notCreated"`
	NotUpdated   map[string]SetError                   `json:"notUpdated"`
	NotDestroyed map[string]SetError                   `json:"notDestroyed"`
}

// Failed reports every refusal as one error ("" ids sorted by kind), or nil.
func (r SetResult) Failed() error {
	var msgs []string
	for id, e := range r.NotCreated {
		msgs = append(msgs, fmt.Sprintf("create %s: %s", id, e))
	}
	for id, e := range r.NotUpdated {
		msgs = append(msgs, fmt.Sprintf("update %s: %s", id, e))
	}
	for id, e := range r.NotDestroyed {
		msgs = append(msgs, fmt.Sprintf("destroy %s: %s", id, e))
	}
	if len(msgs) == 0 {
		return nil
	}
	sort.Strings(msgs)
	return fmt.Errorf("stalwart: %v", msgs)
}

// CreatedID is the server id of a creation, or "".
func (r SetResult) CreatedID(creationID string) string {
	var id string
	if c, ok := r.Created[creationID]; ok {
		_ = json.Unmarshal(c["id"], &id)
	}
	return id
}

// Set creates, updates and destroys objects of one type (object without
// the "x:" prefix, e.g. "Domain"). Refusals are in the result, not err.
func (c *Client) Set(ctx context.Context, object string, create map[string]any, update map[string]map[string]any, destroy []string) (SetResult, error) {
	args := map[string]any{}
	if len(create) > 0 {
		args["create"] = create
	}
	if len(update) > 0 {
		args["update"] = update
	}
	if len(destroy) > 0 {
		args["destroy"] = destroy
	}
	var r SetResult
	err := c.Call(ctx, "x:"+object+"/set", args, &r)
	return r, err
}

// Query returns every id matching filter (nil = all), page by page.
func (c *Client) Query(ctx context.Context, object string, filter any) ([]string, error) {
	var all []string
	seen := map[string]bool{}
	for page := 0; page < 10000; page++ {
		args := map[string]any{"position": len(all)}
		if filter != nil {
			args["filter"] = filter
		}
		var r struct {
			IDs   []string `json:"ids"`
			Total *int     `json:"total"`
		}
		if err := c.Call(ctx, "x:"+object+"/query", args, &r); err != nil {
			return nil, err
		}
		fresh := 0
		for _, id := range r.IDs {
			if !seen[id] {
				seen[id] = true
				all = append(all, id)
				fresh++
			}
		}
		// The last page: nothing new, or the total reached. A server
		// that ignored `position` repeats ids and stops here too.
		if fresh == 0 || (r.Total != nil && len(all) >= *r.Total) {
			return all, nil
		}
	}
	return nil, fmt.Errorf("stalwart: x:%s/query: too many pages", object)
}

// getChunk bounds the ids of one /get.
const getChunk = 256

// Get reads objects into out, a pointer to a slice; ids nil = every
// object (a singleton's id is "singleton"); props nil = every property.
func (c *Client) Get(ctx context.Context, object string, ids []string, props []string, out any) error {
	var lists []json.RawMessage
	fetch := func(chunk []string) error {
		args := map[string]any{"ids": chunk}
		if props != nil {
			args["properties"] = props
		}
		var r struct {
			List json.RawMessage `json:"list"`
		}
		if err := c.Call(ctx, "x:"+object+"/get", args, &r); err != nil {
			return err
		}
		lists = append(lists, r.List)
		return nil
	}
	if ids == nil {
		if err := fetch(nil); err != nil {
			return err
		}
	}
	for i := 0; i < len(ids); i += getChunk {
		if err := fetch(ids[i:min(i+getChunk, len(ids))]); err != nil {
			return err
		}
	}
	return joinLists(lists, out)
}

func joinLists(lists []json.RawMessage, out any) error {
	var items []json.RawMessage
	for _, l := range lists {
		if len(l) == 0 || string(l) == "null" {
			continue
		}
		var part []json.RawMessage
		if err := json.Unmarshal(l, &part); err != nil {
			return fmt.Errorf("stalwart: /get list: %w", err)
		}
		items = append(items, part...)
	}
	if items == nil {
		items = []json.RawMessage{}
	}
	b, _ := json.Marshal(items)
	return json.Unmarshal(b, out)
}

// Action runs one x:Action (ReloadSettings, InvalidateCaches, ...).
func (c *Client) Action(ctx context.Context, variant string) error {
	r, err := c.Set(ctx, "Action", map[string]any{"a": map[string]any{"@type": variant}}, nil, nil)
	if err != nil {
		return err
	}
	if err := r.Failed(); err != nil {
		return err
	}
	if r.CreatedID("a") == "" {
		return fmt.Errorf("stalwart: action %s: no id in the answer", variant)
	}
	return nil
}
