package hubapi

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const secret = "0123456789abcdef0123456789abcdef-hub"

// fakeHub is the Hub's MCP listener (Task 13 builds the real one): it
// checks the secret in constant time like the Hub must, decodes bodies
// strictly and answers what the test says.
type fakeHub struct {
	t   *testing.T
	srv *httptest.Server

	mu      sync.Mutex
	reqs    []recorded
	answer  func(path string, body map[string]any) (int, string)
	hangFor time.Duration
}

type recorded struct {
	Method, Path string
	Header       http.Header
	Body         map[string]any
	Raw          string
}

func newFakeHub(t *testing.T) *fakeHub {
	h := &fakeHub{t: t}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		_ = dec.Decode(&body)
		h.mu.Lock()
		h.reqs = append(h.reqs, recorded{r.Method, r.URL.Path, r.Header.Clone(), body, string(raw)})
		ans, hang := h.answer, h.hangFor
		h.mu.Unlock()
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Portcullis-MCP-Secret")), []byte(secret)) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if hang > 0 {
			select {
			case <-time.After(hang):
			case <-r.Context().Done():
				return
			}
		}
		code, out := 500, ""
		if ans != nil {
			code, out = ans(r.URL.Path, body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = io.WriteString(w, out)
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *fakeHub) set(code int, body string) {
	h.mu.Lock()
	h.answer = func(string, map[string]any) (int, string) { return code, body }
	h.mu.Unlock()
}

func (h *fakeHub) last() recorded {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.reqs) == 0 {
		h.t.Fatal("no request")
	}
	return h.reqs[len(h.reqs)-1]
}

func client(t *testing.T, h *fakeHub, sec string) *Client {
	t.Helper()
	c, err := New(h.srv.URL, sec)
	if err != nil {
		t.Fatal(err)
	}
	c.timeout = 2 * time.Second
	return c
}

const gitea = "https://gitea.example.com/mcp"

func TestMint(t *testing.T) {
	h := newFakeHub(t)
	c := client(t, h, secret)
	ctx := context.Background()

	h.set(200, `{"id":"7"}`)
	a, err := c.Mint(ctx, gitea, "alice")
	if err != nil || a.ID != "7" {
		t.Fatalf("200: %+v %v", a, err)
	}
	r := h.last()
	if r.Method != "POST" || r.Path != "/internal/credentials" || r.Header.Get("Content-Type") != "application/json" {
		t.Errorf("request %+v", r)
	}
	if r.Raw != `{"resource":"https://gitea.example.com/mcp","user":"alice"}` {
		t.Errorf("body %s", r.Raw)
	}
	for _, hd := range []string{"Authorization", "Cookie", "X-Forwarded-User"} {
		if r.Header.Get(hd) != "" {
			t.Errorf("%s sent", hd)
		}
	}

	h.set(409, `{"code":"no_account","app_url":"https://gitea.example.com"}`)
	a, err = c.Mint(ctx, gitea, "alice")
	if !errors.Is(err, ErrNoAccount) || a == nil || a.AppURL != "https://gitea.example.com" {
		t.Errorf("409 no_account: %+v %v", a, err)
	}

	for _, tc := range []struct {
		code int
		body string
		want error
	}{
		{403, ``, ErrNotAllowed},
		{404, ``, ErrUnknownResource},
		{502, `{"code":"mint_failed"}`, ErrMintFailed},
		// G26: everything not listed fails closed.
		{502, `{"code":"other"}`, ErrUnavailable},
		{502, ``, ErrUnavailable},
		{500, `{"id":"7"}`, ErrUnavailable},
		{503, ``, ErrUnavailable},
		{201, `{"id":"7"}`, ErrUnavailable},
		{204, ``, ErrUnavailable},
		{409, `{"code":"pending"}`, ErrUnavailable},
		{409, `{"code":"no_account"}`, ErrUnavailable}, // app_url missing
		{409, `{"code":"no_account","app_url":"javascript:alert(1)"}`, ErrUnavailable},
		{200, `{"id":""}`, ErrUnavailable},
		{200, `{"id":"7","credential":"x"}`, ErrUnavailable},
		{200, `{"id":"7"} {}`, ErrUnavailable},
		{200, `{"id":"7"`, ErrUnavailable},
		{200, `{"id":7}`, ErrUnavailable},
		{200, `{"id":"has space"}`, ErrUnavailable},
		{200, `{"ID":"7"}`, ErrUnavailable},
		{200, `{"id":"7","id":"8"}`, ErrUnavailable},
		{200, `null`, ErrUnavailable},
		{200, `{"id":"` + strings.Repeat("a", 70000) + `"}`, ErrUnavailable},
	} {
		h.set(tc.code, tc.body)
		_, err := c.Mint(ctx, gitea, "alice")
		if !errors.Is(err, tc.want) {
			t.Errorf("%d %.40s: %v, want %v", tc.code, tc.body, err, tc.want)
		}
	}
}

// G26: wrong secret, Hub down, timeouts and redirects all fail closed;
// errors never carry the secret or the Hub's body.
func TestFailClosed(t *testing.T) {
	h := newFakeHub(t)
	ctx := context.Background()
	h.set(200, `{"id":"7"}`)

	wrong := client(t, h, strings.Repeat("x", 40))
	if _, err := wrong.Mint(ctx, gitea, "alice"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("wrong secret: %v", err)
	}
	if id, st, err := wrong.ConsumeConfirmation(ctx, ConsumeRequest{User: "alice", Resource: gitea, Tool: "delete_repo", ArgsSHA256: strings.Repeat("0", 64)}); !errors.Is(err, ErrUnavailable) || id != "" || st != "" {
		t.Errorf("wrong secret consume: %q %q %v", id, st, err)
	}

	c := client(t, h, secret)
	h.mu.Lock()
	h.hangFor = 5 * time.Second
	h.mu.Unlock()
	c.timeout = 200 * time.Millisecond
	start := time.Now()
	if _, err := c.Mint(ctx, gitea, "alice"); !errors.Is(err, ErrUnavailable) || time.Since(start) > 2*time.Second {
		t.Errorf("timeout: %v after %v", err, time.Since(start))
	}
	cctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	c.timeout = 10 * time.Second
	if _, err := c.Mint(cctx, gitea, "alice"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("caller deadline: %v", err)
	}
	h.mu.Lock()
	h.hangFor = 0
	h.mu.Unlock()

	// A redirect is never followed.
	var hit bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true; _, _ = io.WriteString(w, `{"id":"7"}`) }))
	defer target.Close()
	h.mu.Lock()
	h.answer = func(string, map[string]any) (int, string) { return 0, "" }
	h.mu.Unlock()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	rc, _ := New(redir.URL, secret)
	if _, err := rc.Mint(ctx, gitea, "alice"); !errors.Is(err, ErrUnavailable) || hit {
		t.Errorf("redirect: %v, target hit %v", err, hit)
	}

	// The Hub down.
	down, _ := New("http://127.0.0.1:1", secret)
	_, err := down.Mint(ctx, gitea, "alice")
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("down: %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Error("the secret is in an error")
	}
	h.set(500, `{"secret":"`+secret+`","detail":"boom"}`)
	if _, err := c.Mint(ctx, gitea, "alice"); err == nil || strings.Contains(err.Error(), "boom") || strings.Contains(err.Error(), secret) {
		t.Errorf("Hub body in the error: %v", err)
	}
}

func TestNewRefuses(t *testing.T) {
	for _, tc := range []struct{ url, sec string }{
		{"http://hub:8890", strings.Repeat("a", 31)},
		{"http://hub:8890", strings.Repeat("a", 32) + "\n"},
		{"http://hub:8890", strings.Repeat("a", 32) + "\x00"},
		{"http://hub:8890/x", secret},
		{"http://hub:8890?x=1", secret},
		{"ftp://hub:8890", secret},
		{"http://user:pw@hub:8890", secret},
		{"hub:8890", secret},
	} {
		if _, err := New(tc.url, tc.sec); err == nil {
			t.Errorf("New(%q, %d chars) accepted", tc.url, len(tc.sec))
		} else if strings.Contains(err.Error(), tc.sec) {
			t.Error("secret in the error")
		}
	}
	if _, err := New("http://hub:8890", secret); err != nil {
		t.Error(err)
	}
	if _, err := New("http://hub:8890/", secret); err != nil {
		t.Error(err)
	}
}

func validConfirm() ConfirmRequest {
	return ConfirmRequest{
		User: "alice", Client: "portcullis-ai-claude", Resource: gitea, Tool: "delete_repo",
		ArgsSHA256: strings.Repeat("a1", 32), ArgsPreview: `{"repo":"x"}`, Reason: "confirm",
	}
}

const cid = "7Q2MK7WXABCDEFGHIJKLMNOPQR"

func TestCreateConfirmation(t *testing.T) {
	h := newFakeHub(t)
	c := client(t, h, secret)
	ctx := context.Background()
	exp := "2026-11-05T10:26:02Z"
	h.set(201, `{"id":"`+cid+`","url":"https://people.example.com/confirm/`+cid+`","expires_at":"`+exp+`"}`)
	got, err := c.CreateConfirmation(ctx, validConfirm())
	if err != nil || got.ID != cid || got.URL != "https://people.example.com/confirm/"+cid || !got.ExpiresAt.Equal(time.Date(2026, 11, 5, 10, 26, 2, 0, time.UTC)) {
		t.Fatalf("201: %+v %v", got, err)
	}
	r := h.last()
	if r.Path != "/internal/confirmations" ||
		r.Raw != `{"user":"alice","client":"portcullis-ai-claude","resource":"https://gitea.example.com/mcp","tool":"delete_repo","args_sha256":"`+strings.Repeat("a1", 32)+`","args_preview":"{\"repo\":\"x\"}","reason":"confirm"}` {
		t.Errorf("request %s %s", r.Path, r.Raw)
	}
	// The dashed display form is accepted when the URL names the same id.
	dashed := "7Q2M-K7WX-ABCD-EFGH-IJKL-MNOP-QR"
	h.set(201, `{"id":"`+dashed+`","url":"https://people.example.com/confirm/`+dashed+`","expires_at":"`+exp+`"}`)
	if got, err := c.CreateConfirmation(ctx, validConfirm()); err != nil || got.ID != dashed {
		t.Errorf("dashed: %+v %v", got, err)
	}

	for _, tc := range []struct {
		code int
		body string
		want error
	}{
		{403, ``, ErrNotAllowed},
		{404, ``, ErrUnknownResource},
		{400, ``, ErrNotConfirmable},
		{429, `{"code":"too_many"}`, ErrTooMany},
		{429, `{}`, ErrUnavailable},
		{200, `{"id":"` + cid + `","url":"https://people.example.com/confirm/` + cid + `","expires_at":"` + exp + `"}`, ErrUnavailable},
		{201, `{"id":"` + cid + `","url":"https://people.example.com/confirm/OTHER","expires_at":"` + exp + `"}`, ErrUnavailable},
		{201, `{"id":"` + cid + `","url":"http://people.example.com/confirm/` + cid + `","expires_at":"` + exp + `"}`, ErrUnavailable},
		{201, `{"id":"` + cid + `","url":"https://u@people.example.com/confirm/` + cid + `","expires_at":"` + exp + `"}`, ErrUnavailable},
		{201, `{"id":"` + cid + `","url":"https://people.example.com/confirm/` + cid + `?x","expires_at":"` + exp + `"}`, ErrUnavailable},
		{201, `{"id":"short","url":"https://people.example.com/confirm/short","expires_at":"` + exp + `"}`, ErrUnavailable},
		{201, `{"id":"` + cid + `","url":"https://people.example.com/confirm/` + cid + `","expires_at":"soon"}`, ErrUnavailable},
		{201, `{"id":"` + cid + `","url":"https://people.example.com/confirm/` + cid + `"}`, ErrUnavailable},
		{500, ``, ErrUnavailable},
	} {
		h.set(tc.code, tc.body)
		_, err := c.CreateConfirmation(ctx, validConfirm())
		if !errors.Is(err, tc.want) {
			t.Errorf("%d %.60s: %v, want %v", tc.code, tc.body, err, tc.want)
		}
	}

	// Requests the gate must never send are refused before the Hub.
	n := len(h.reqs)
	for name, mut := range map[string]func(*ConfirmRequest){
		"reason":   func(r *ConfirmRequest) { r.Reason = "other" },
		"digest":   func(r *ConfirmRequest) { r.ArgsSHA256 = strings.Repeat("A1", 32) },
		"short":    func(r *ConfirmRequest) { r.ArgsSHA256 = "ab" },
		"preview":  func(r *ConfirmRequest) { r.ArgsPreview = strings.Repeat("x", 4097) },
		"user":     func(r *ConfirmRequest) { r.User = "" },
		"tool":     func(r *ConfirmRequest) { r.Tool = "" },
		"resource": func(r *ConfirmRequest) { r.Resource = "" },
	} {
		req := validConfirm()
		mut(&req)
		if _, err := c.CreateConfirmation(ctx, req); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if len(h.reqs) != n {
		t.Error("an invalid request reached the Hub")
	}
}

func TestConsumeConfirmation(t *testing.T) {
	h := newFakeHub(t)
	c := client(t, h, secret)
	ctx := context.Background()
	req := ConsumeRequest{User: "alice", Resource: gitea, Tool: "delete_repo", ArgsSHA256: strings.Repeat("0f", 32)}

	h.set(200, `{"id":"`+cid+`"}`)
	id, st, err := c.ConsumeConfirmation(ctx, req)
	if err != nil || id != cid || st != StateConsumed {
		t.Fatalf("200: %q %q %v", id, st, err)
	}
	if r := h.last(); r.Path != "/internal/confirmations/consume" || r.Raw != `{"user":"alice","resource":"https://gitea.example.com/mcp","tool":"delete_repo","args_sha256":"`+strings.Repeat("0f", 32)+`"}` {
		t.Errorf("request %s %s", r.Path, r.Raw)
	}
	for _, tc := range []struct {
		code      int
		body      string
		wantState string
		wantErr   error
	}{
		{404, ``, StateNone, nil},
		{409, `{"state":"pending"}`, StatePending, nil},
		{409, `{"state":"declined"}`, StateDeclined, nil},
		{409, `{"state":"approved"}`, "", ErrUnavailable},
		{409, `{}`, "", ErrUnavailable},
		{200, `{"id":""}`, "", ErrUnavailable},
		{200, `{}`, "", ErrUnavailable},
		{201, `{"id":"` + cid + `"}`, "", ErrUnavailable},
		{403, ``, "", ErrUnavailable},
		{500, ``, "", ErrUnavailable},
		{502, ``, "", ErrUnavailable},
	} {
		h.set(tc.code, tc.body)
		id, st, err := c.ConsumeConfirmation(ctx, req)
		if st != tc.wantState || !errors.Is(err, tc.wantErr) || (err != nil && id != "") {
			t.Errorf("%d %s: %q %q %v", tc.code, tc.body, id, st, err)
		}
	}
	bad := req
	bad.ArgsSHA256 = "x"
	if _, _, err := c.ConsumeConfirmation(ctx, bad); err == nil {
		t.Error("bad digest accepted")
	}
}
