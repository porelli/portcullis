package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/portcullis/mailctl/internal/stalwart"
)

// fakeStalwart is an in-memory JMAP management API: /get, /query, /set on
// any x: object (singletons under id "singleton"), ApiKeys per accountId.
type fakeStalwart struct {
	mu      sync.Mutex
	objs    map[string]map[string]map[string]any // object → id → fields
	next    int
	calls   []string // "x:Obj/set create" etc.
	refuse  map[string]string
	keyNext int
}

func newFake() *fakeStalwart {
	return &fakeStalwart{objs: map[string]map[string]map[string]any{}, refuse: map[string]string{}}
}

func (f *fakeStalwart) put(obj string, fields map[string]any) string {
	if f.objs[obj] == nil {
		f.objs[obj] = map[string]map[string]any{}
	}
	f.next++
	id := fmt.Sprintf("id%d", f.next)
	cp := map[string]any{}
	for k, v := range normalize(fields).(map[string]any) {
		cp[k] = v
	}
	f.objs[obj][id] = cp
	return id
}

func (f *fakeStalwart) named(obj, key string) []string {
	var out []string
	for _, o := range f.objs[obj] {
		out = append(out, fmt.Sprint(o[key]))
	}
	return out
}

func (f *fakeStalwart) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var req struct {
		MethodCalls [][3]json.RawMessage `json:"methodCalls"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	var method string
	json.Unmarshal(req.MethodCalls[0][0], &method)
	var args map[string]json.RawMessage
	json.Unmarshal(req.MethodCalls[0][1], &args)
	obj := strings.TrimPrefix(strings.Split(method, "/")[0], "x:")
	verb := strings.Split(method, "/")[1]
	var acct string
	json.Unmarshal(args["accountId"], &acct)
	store := obj
	if obj == "ApiKey" {
		store = "ApiKey@" + acct
	}
	var out any
	switch verb {
	case "query":
		var ids []string
		var pos int
		json.Unmarshal(args["position"], &pos)
		if pos == 0 {
			for id := range f.objs[store] {
				ids = append(ids, id)
			}
		}
		out = map[string]any{"ids": ids, "total": len(f.objs[store])}
	case "get":
		var ids []string
		json.Unmarshal(args["ids"], &ids)
		var list []any
		for _, id := range ids {
			if o, ok := f.objs[store][id]; ok {
				c := map[string]any{"id": id}
				for k, v := range o {
					c[k] = v
				}
				list = append(list, c)
			}
		}
		out = map[string]any{"list": list}
	case "set":
		var create map[string]map[string]any
		var update map[string]map[string]any
		var destroy []string
		json.Unmarshal(args["create"], &create)
		json.Unmarshal(args["update"], &update)
		json.Unmarshal(args["destroy"], &destroy)
		res := map[string]any{}
		if len(create) > 0 {
			f.calls = append(f.calls, method+" create")
			created := map[string]any{}
			notCreated := map[string]any{}
			for cid, o := range create {
				if why := f.refuse[obj]; why != "" {
					notCreated[cid] = map[string]any{"type": "forbidden", "description": why}
					continue
				}
				id := f.put(store, o)
				c := map[string]any{"id": id}
				if obj == "ApiKey" {
					f.keyNext++
					c["secret"] = fmt.Sprintf("API_%038d", f.keyNext)
				}
				created[cid] = c
			}
			res["created"], res["notCreated"] = created, notCreated
		}
		if len(update) > 0 {
			f.calls = append(f.calls, method+" update")
			updated := map[string]any{}
			for id, p := range update {
				if f.objs[store] == nil {
					f.objs[store] = map[string]map[string]any{}
				}
				if f.objs[store][id] == nil {
					f.objs[store][id] = map[string]any{}
				}
				for k, v := range normalize(p).(map[string]any) {
					f.objs[store][id][k] = v
				}
				updated[id] = nil
			}
			res["updated"] = updated
		}
		if len(destroy) > 0 {
			f.calls = append(f.calls, method+" destroy")
			for _, id := range destroy {
				delete(f.objs[store], id)
			}
			res["destroyed"] = destroy
		}
		out = res
	}
	json.NewEncoder(w).Encode(map[string]any{"methodResponses": []any{[]any{method, out, "0"}}})
}

func params() Params {
	return Params{
		Hostname: "mail.example.com", PrimaryDomain: "example.com", MailctlIP: netip.MustParseAddr("172.31.255.3"),
		ResolverIP: netip.MustParseAddr("172.31.255.4"), ResolverPort: 5353, RulesURL: "http://172.31.255.3:8082/spam-filter-rules.json.gz",
		ClientIP: "preserved", MetricsUser: "prometheus",
		HTTPLookups: []map[string]any{{"namespace": "stwt_openphish", "url": "https://openphish.com/feed.txt", "format": map[string]any{"@type": "List"}, "enable": true}},
	}
}

func seedDefaults(f *fakeStalwart) {
	for _, l := range []struct{ name, proto, bind string }{
		{"smtp", "smtp", "[::]:25"}, {"submissions", "smtp", "[::]:465"}, {"imaps", "imap", "[::]:993"},
		{"pop3s", "pop3", "[::]:995"}, {"sieve", "manageSieve", "[::]:4190"}, {"https", "http", "[::]:443"}, {"http", "http", "[::]:8080"},
	} {
		f.put("NetworkListener", map[string]any{"name": l.name, "protocol": l.proto, "bind": map[string]bool{l.bind: true}})
	}
	f.put("Tracer", map[string]any{"@type": "Log", "path": "/var/log/stalwart"})
	f.put("Application", map[string]any{"enable": true, "description": "WebUI"})
	f.put("AcmeProvider", map[string]any{"description": "LE"})
	f.put("Domain", map[string]any{"name": "example.com", "dkimManagement": map[string]any{"@type": "Automatic"}})
	f.put("Certificate", map[string]any{"certificate": map[string]any{"@type": "Text", "value": "self-signed"}})
}

func run(t *testing.T, f *fakeStalwart, p Params, rotate bool) Result {
	t.Helper()
	srv := httptest.NewServer(f)
	defer srv.Close()
	res, err := Apply(context.Background(), stalwart.New(srv.URL, stalwart.Basic("r", "p")), p, rotate, nil)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestBasePlanIsIdempotent(t *testing.T) {
	f := newFake()
	seedDefaults(f)
	run(t, f, params(), false)
	f.calls = nil
	run(t, f, params(), false)
	for _, c := range f.calls {
		if strings.HasSuffix(c, " create") && c != "x:Action/set create" {
			t.Errorf("second run created: %s", c)
		}
		if strings.HasSuffix(c, " destroy") {
			t.Errorf("second run destroyed: %s", c)
		}
	}
}

func TestBasePlanDeletesDefaultListeners(t *testing.T) {
	f := newFake()
	seedDefaults(f)
	run(t, f, params(), false)
	got := strings.Join(sorted(f.named("NetworkListener", "name")), ",")
	if got != "admin-view,imaps,management,metrics,smtp,submission,submissions" {
		t.Fatalf("listeners %s", got)
	}
	for _, o := range f.objs["NetworkListener"] {
		if o["name"] == "management" {
			b := o["bind"].(map[string]any)
			// Ruling T17-b: the wildcard, never loopback only (the adapter
			// reaches the real server on the internal network).
			if len(b) != 1 || b["[::]:8080"] != true {
				t.Fatalf("management bind %v", b)
			}
		}
		if o["name"] == "smtp" && o["bind"].(map[string]any)["[::]:10025"] != true {
			t.Fatalf("smtp bind %v", o["bind"])
		}
	}
	if len(f.objs["AcmeProvider"]) != 0 {
		t.Fatal("an ACME provider is left")
	}
	if got := sorted(f.named("Tracer", "@type")); strings.Join(got, ",") != "Stdout" {
		t.Fatalf("tracers %v", got)
	}
	// The web admin only at /admin, from the pinned bundle (contract
	// §19.13): never the /account self-service, never a download.
	for _, a := range f.objs["Application"] {
		prefixes, _ := a["urlPrefix"].(map[string]any)
		if a["enable"] != true || len(prefixes) != 1 || prefixes["/admin"] != true || a["resourceUrl"] != "file://"+WebUIBundle {
			t.Fatalf("the WebUI is %v", a)
		}
	}
	for _, d := range f.objs["Domain"] {
		if d["dkimManagement"].(map[string]any)["@type"] != "Manual" || d["certificateManagement"].(map[string]any)["@type"] != "Manual" {
			t.Fatalf("domain %v not Manual", d["name"])
		}
	}
	if len(f.objs["Certificate"]) != 1 {
		t.Fatalf("%d certificates", len(f.objs["Certificate"]))
	}
	for _, l := range f.objs["HttpLookup"] {
		if l["enable"] != false {
			t.Fatal("an external lookup is enabled")
		}
	}
	if !contains(f.named("Domain", "name"), ParkingDomain) {
		t.Fatal("no parking domain")
	}
}

func TestBasePlanRoleHasNoSelfWidening(t *testing.T) {
	f := newFake()
	run(t, f, params(), false)
	for _, r := range f.objs["Role"] {
		if r["description"] != MailctlRole {
			continue
		}
		perms := r["enabledPermissions"].(map[string]any)
		for p := range perms {
			for _, bad := range []string{"sysApiKey", "sysRole", "jmap", "dav", "sieve", "pop3"} {
				if strings.HasPrefix(p, bad) {
					t.Errorf("role holds %s", p)
				}
			}
		}
		for _, p := range append([]string{"actionReloadLookupStores", "sysHttpLookupUpdate"}, stalwart.MailPasswordPermissions...) {
			if perms[p] != true {
				t.Errorf("role lacks %s", p)
			}
		}
		return
	}
	t.Fatal("no role portcullis-mailctl")
}

func TestBasePlanRelayStrictTLS(t *testing.T) {
	p := params()
	p.Relay = &Relay{Host: "smtp.relay.example", Port: 587, Username: "u"}
	f := newFake()
	run(t, f, p, false)
	if !contains(f.named("MtaTlsStrategy", "name"), "relay-strict") {
		t.Fatal("no relay-strict strategy")
	}
	for _, s := range f.objs["MtaTlsStrategy"] {
		if s["name"] == "relay-strict" && s["startTls"] != "require" {
			t.Fatal("relay-strict doesn't require STARTTLS")
		}
	}
	var relay map[string]any
	for _, r := range f.objs["MtaRoute"] {
		if r["name"] == "relay" {
			relay = r
		}
	}
	if relay == nil || relay["host"] != "smtp.relay.example" || relay["implicitTls"] != false || relay["authSecret"].(map[string]any)["filePath"] != RelaySecret {
		t.Fatalf("relay route %v", relay)
	}
	ob := f.objs["MtaOutboundStrategy"]["singleton"]
	if ob["tls"].(map[string]any)["else"] != "'relay-strict'" || ob["route"].(map[string]any)["else"] != "'relay'" {
		t.Fatalf("outbound %v", ob)
	}
	// Without a relay the next run removes nothing it doesn't own, but the
	// outbound strategy goes back to mx / default.
	run(t, f, params(), false)
	ob = f.objs["MtaOutboundStrategy"]["singleton"]
	if ob["tls"].(map[string]any)["else"] != "'default'" || ob["route"].(map[string]any)["else"] != "'mx'" {
		t.Fatalf("outbound without relay %v", ob)
	}
}

func TestBootstrapPrintsKeyOnce(t *testing.T) {
	f := newFake()
	if k := run(t, f, params(), false).APIKey; !strings.HasPrefix(k, "API_") {
		t.Fatalf("first run key %q", k)
	}
	if k := run(t, f, params(), false).APIKey; k != "" {
		t.Fatalf("second run printed a key")
	}
	if k := run(t, f, params(), true).APIKey; !strings.HasPrefix(k, "API_") {
		t.Fatal("--rotate-key printed no key")
	}
	n := 0
	for s, objs := range f.objs {
		if strings.HasPrefix(s, "ApiKey@") {
			n += len(objs)
			for _, k := range objs {
				ips := k["allowedIps"].(map[string]any)
				// The adapter's /32 only (Ruling R2-N2b).
				if len(ips) != 1 || ips["172.31.255.3/32"] != true || k["permissions"].(map[string]any)["@type"] != "Inherit" {
					t.Fatalf("api key %v", k)
				}
			}
		}
	}
	if n != 1 {
		t.Fatalf("%d API keys after a rotation", n)
	}
}

func TestBootstrapSurfacesRefusal(t *testing.T) {
	f := newFake()
	f.refuse["ApiKey"] = "not authorized"
	srv := httptest.NewServer(f)
	defer srv.Close()
	_, err := Apply(context.Background(), stalwart.New(srv.URL, stalwart.Basic("r", "p")), params(), false, nil)
	if err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("refusal not surfaced: %v", err)
	}
}

func TestVerifyGoneRefusesWhenLoginWorks(t *testing.T) {
	for code, ok := range map[int]bool{401: true, 200: false, 404: false, 500: false} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if u, p, _ := r.BasicAuth(); u != "portcullis-recovery" || p != "pw" {
				t.Errorf("credentials %q %q", u, p)
			}
			w.WriteHeader(code)
		}))
		err := VerifyGone(context.Background(), srv.URL, Credentials{"portcullis-recovery", "pw"})
		srv.Close()
		if (err == nil) != ok {
			t.Errorf("HTTP %d: %v", code, err)
		}
		if code == 200 && err != ErrStillWorks {
			t.Errorf("200: %v", err)
		}
	}
	if err := VerifyGone(context.Background(), "http://127.0.0.1:1", Credentials{"a", "b"}); err == nil {
		t.Error("no answer counted as gone")
	}
}

// Every stock `local_port == 25` / `!= 25` default (Task 2: 13 of them)
// is set by the plan, and no plan expression keys on port 25.
func TestPlanRewritesEveryPort25Default(t *testing.T) {
	raw, err := os.ReadFile("../stalwart/testdata/schema-v1.1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Fields map[string]struct {
			Defaults map[string]json.RawMessage `json:"defaults"`
		} `json:"fields"`
	}
	json.Unmarshal(raw, &s)
	set := map[string]map[string]any{}
	for _, sg := range params().Singletons() {
		set["x:"+sg.Object] = sg.Patch
	}
	n := 0
	for obj, f := range s.Fields {
		for field, d := range f.Defaults {
			if strings.Contains(string(d), "local_port") {
				n++
				if _, ok := set[obj][field]; !ok {
					t.Errorf("%s.%s keeps its port-25 default", obj, field)
				}
			}
		}
	}
	if n != 13 {
		t.Errorf("%d port-25 defaults in the schema, want 13", n)
	}
	b, _ := json.Marshal(params().Singletons())
	for _, bad := range []string{"local_port == 25", "local_port != 25"} {
		if strings.Contains(string(b), bad) {
			t.Errorf("the plan still says %s", bad)
		}
	}
}

func TestDegradedSenderAuth(t *testing.T) {
	p := params()
	p.ClientIP = "rewritten"
	sa := p.senderAuth()
	for _, k := range []string{"spfEhloVerify", "spfFromVerify", "reverseIpVerify"} {
		if e := sa[k].(map[string]any); e["else"] != "disable" || len(e["match"].(map[string]any)) != 0 {
			t.Errorf("%s not off in degraded mode: %v", k, e)
		}
	}
}

// Review Focus 1: the degraded plan's values, exactly.
func TestClientIPRewrittenPlanDisablesIPChecks(t *testing.T) {
	p := params()
	p.ClientIP = "rewritten"
	got, _ := json.Marshal(p.senderAuth())
	want := `{"arcVerify":{"else":"disable","match":{"0":{"if":"local_port == 10025","then":"relaxed"}}},` +
		`"dkimVerify":{"else":"disable","match":{"0":{"if":"local_port == 10025","then":"relaxed"}}},` +
		`"dmarcVerify":{"else":"disable","match":{"0":{"if":"local_port == 10025","then":"relaxed"}}},` +
		`"reverseIpVerify":{"else":"disable","match":{}},"spfEhloVerify":{"else":"disable","match":{}},"spfFromVerify":{"else":"disable","match":{}}}`
	if string(got) != want {
		t.Fatalf("degraded SenderAuth\n got %s\nwant %s", got, want)
	}
	var sec map[string]any
	for _, s := range p.Singletons() {
		if s.Object == "Security" {
			sec = s.Patch
		}
	}
	if b, _ := json.Marshal(sec); string(b) != `{"abuseBanRate":null,"authBanRate":null,"loiterBanRate":null,"scanBanRate":null}` {
		t.Fatalf("degraded Security %s", b)
	}
	p.ClientIP = "preserved"
	// Preserved addresses: Stalwart's default ban rates, written
	// explicitly (leaving degraded mode restores the bans).
	for _, s := range p.Singletons() {
		if s.Object == "Security" {
			if b, _ := json.Marshal(s.Patch); string(b) != `{"abuseBanRate":{"count":35,"period":86400000},"authBanRate":{"count":100,"period":86400000},"loiterBanRate":{"count":150,"period":86400000},"scanBanRate":{"count":30,"period":86400000}}` {
				t.Fatalf("normal Security %s", b)
			}
		}
	}
	if b, _ := json.Marshal(p.senderAuth()["spfFromVerify"]); string(b) != `{"else":"disable","match":{"0":{"if":"local_port == 10025","then":"relaxed"}}}` {
		t.Fatalf("preserved SPF %s", b)
	}
}

// The allow / block rules: allow needs DMARC, both by domain or address.
func TestSpamListRules(t *testing.T) {
	var rules []map[string]any
	for _, n := range params().Collections() {
		if n.Object == "SpamRule" {
			rules = n.Want
		}
	}
	if len(rules) != 2 {
		t.Fatalf("%v", rules)
	}
	b, _ := json.Marshal(rules)
	for _, w := range []string{
		`$DMARC_POLICY_ALLOW \u0026\u0026 (key_exists('portcullis-allow', from.domain) || key_exists('portcullis-allow', from.local + '@' + from.domain))`,
		`"then":"'TRUSTED_DOMAIN'"`, `"then":"'BLOCKED_DOMAIN'"`,
		`(key_exists('portcullis-block', from.domain) || key_exists('portcullis-block', from.local + '@' + from.domain))`,
	} {
		if !strings.Contains(string(b), w) {
			t.Errorf("missing %s in %s", w, b)
		}
	}
}

func TestAllowedEndpointsPinsMailctl(t *testing.T) {
	b := fmt.Sprint(params().AllowedEndpoints())
	for _, want := range []string{"listener == 'management' && remote_ip == '172.31.255.3'", "listener == 'metrics' && path == '/metrics/prometheus'", "else:404"} {
		if !strings.Contains(b, want) {
			t.Errorf("rule lacks %s: %s", want, b)
		}
	}
}

func TestEveryUsedFieldInSchema(t *testing.T) {
	raw, err := os.ReadFile("../stalwart/testdata/schema-v1.1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := stalwart.ParseSchema(raw)
	if err != nil {
		t.Fatal(err)
	}
	if bad := s.Check(stalwart.Used); len(bad) > 0 {
		t.Fatalf("not in the schema:\n%s", strings.Join(bad, "\n"))
	}
}

func sorted(s []string) []string {
	out := append([]string(nil), s...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// The From check (security ruling): exactly one From: header with exactly
// one address equal to the envelope sender, and a sender at all. Checked
// live against Stalwart v1.1.0 (task-6-report.md); here its shape.
func TestFromCheckSieveShape(t *testing.T) {
	for _, want := range []string{
		`require ["envelope", "variables", "reject", "relational", "comparator-i;ascii-numeric"];`,
		`if not envelope :matches "from" "?*"`,
		`if header :count "ne" :comparator "i;ascii-numeric" "from" "1"`,
		`if address :count "ne" :comparator "i;ascii-numeric" :all "from" "1"`,
		`if not address :all :is "from" "${ef}"`,
	} {
		if !strings.Contains(FromCheckSieve, want) {
			t.Errorf("from-check lacks %s", want)
		}
	}
	if strings.Count(FromCheckSieve, "reject ") != 4 || strings.Count(FromCheckSieve, "stop;") != 4 {
		t.Error("every refusal must reject and stop")
	}
	var data map[string]any
	for _, s := range params().Singletons() {
		if s.Object == "MtaStageData" {
			data = s.Patch
		}
	}
	if fmt.Sprint(data["script"]) != fmt.Sprint(expr("false", [2]string{"!is_empty(authenticated_as)", "'from-check'"})) {
		t.Fatalf("MtaStageData.script %v", data["script"])
	}
}

// LAN-only: the base plan writes the SASL rule with the Local networks
// (final review M1); loopback only with rewritten client addresses.
func TestBasePlanSASLLANOnly(t *testing.T) {
	sasl := func(p Params) string {
		for _, s := range p.Singletons() {
			if s.Object == "MtaStageAuth" {
				b, _ := json.Marshal(s.Patch["saslMechanisms"])
				return string(b)
			}
		}
		return ""
	}
	p := params()
	if got := sasl(p); strings.Contains(got, "is_ip_in_cidr") {
		t.Fatalf("not LAN-only: %s", got)
	}
	p.LANOnly, p.LocalNetworks = true, []string{"192.168.1.0/24"}
	if got := sasl(p); !strings.Contains(got, "is_ip_in_cidr(remote_ip, '192.168.1.0/24')") {
		t.Fatalf("LAN-only: %s", got)
	}
	p.ClientIP = "rewritten"
	if got := sasl(p); strings.Contains(got, "192.168.1.0/24") || !strings.Contains(got, "127.0.0.1/32") {
		t.Fatalf("LAN-only, rewritten: %s", got)
	}
}

// KeyInPlace against the shapes real Stalwart 1.1 answers (seen on the
// builder smoke, core fix round 2): allowedIps a set holding the bare
// address, the secret returned in clear, expiresAt null.
func TestKeyInPlaceRealShapes(t *testing.T) {
	ip := netip.MustParseAddr("172.31.255.3")
	for name, c := range map[string]struct {
		key  map[string]any
		file string
		want bool
	}{
		"real shape":       {map[string]any{"description": "mailctl", "permissions": map[string]any{"@type": "Inherit"}, "allowedIps": map[string]any{"172.31.255.3": true}, "secret": "API_x1", "createdAt": "2026-11-17T10:00:00Z", "expiresAt": nil}, "API_x1", true},
		"with /32":         {map[string]any{"description": "mailctl", "permissions": map[string]any{"@type": "Inherit"}, "allowedIps": map[string]any{"172.31.255.3/32": true}}, "API_x1", true},
		"another secret":   {map[string]any{"description": "mailctl", "permissions": map[string]any{"@type": "Inherit"}, "allowedIps": map[string]any{"172.31.255.3": true}, "secret": "API_other"}, "API_x1", false},
		"masked secret":    {map[string]any{"description": "mailctl", "permissions": map[string]any{"@type": "Inherit"}, "allowedIps": map[string]any{"172.31.255.3": true}, "secret": "********"}, "API_x1", true},
		"widened":          {map[string]any{"description": "mailctl", "permissions": map[string]any{"@type": "Inherit"}, "allowedIps": map[string]any{"172.31.255.3": true, "0.0.0.0/0": true}}, "API_x1", false},
		"another address":  {map[string]any{"description": "mailctl", "permissions": map[string]any{"@type": "Inherit"}, "allowedIps": map[string]any{"172.31.255.4": true}}, "API_x1", false},
		"expiring":         {map[string]any{"description": "mailctl", "permissions": map[string]any{"@type": "Inherit"}, "allowedIps": map[string]any{"172.31.255.3": true}, "expiresAt": "2027-01-01T00:00:00Z"}, "API_x1", false},
		"other permission": {map[string]any{"description": "mailctl", "permissions": map[string]any{"@type": "Replace"}, "allowedIps": map[string]any{"172.31.255.3": true}}, "API_x1", false},
		"no key file":      {map[string]any{"description": "mailctl", "permissions": map[string]any{"@type": "Inherit"}, "allowedIps": map[string]any{"172.31.255.3": true}}, "", false},
	} {
		f := newFake()
		d := f.put("Domain", map[string]any{"name": ParkingDomain})
		a := f.put("Account", map[string]any{"name": MailctlAccount, "domainId": d})
		f.put("ApiKey@"+a, c.key)
		srv := httptest.NewServer(f)
		ok, err := KeyInPlace(context.Background(), stalwart.New(srv.URL, stalwart.Basic("r", "p")), ip, c.file)
		srv.Close()
		if err != nil || ok != c.want {
			t.Errorf("%s: %v %v, want %v", name, ok, err, c.want)
		}
	}
	// Two keys (an old one not destroyed): not in place.
	f := newFake()
	d := f.put("Domain", map[string]any{"name": ParkingDomain})
	a := f.put("Account", map[string]any{"name": MailctlAccount, "domainId": d})
	for i := 0; i < 2; i++ {
		f.put("ApiKey@"+a, map[string]any{"description": "mailctl", "permissions": map[string]any{"@type": "Inherit"}, "allowedIps": map[string]any{"172.31.255.3": true}})
	}
	srv := httptest.NewServer(f)
	defer srv.Close()
	if ok, _ := KeyInPlace(context.Background(), stalwart.New(srv.URL, stalwart.Basic("r", "p")), ip, "API_x1"); ok {
		t.Fatal("two keys judged in place")
	}
}

// The admin view (contract §19.13): the viewer role holds exactly the
// read-only list, its account sits on the parking domain with that role
// alone and a password the plan hands back, and the admin-view listener
// answers only the proxy's address.
func TestBasePlanViewer(t *testing.T) {
	f := newFake()
	p := params()
	p.ViewerIP = netip.MustParseAddr("172.31.255.5")
	res := run(t, f, p, false)
	if len(res.ViewerPassword) < 40 {
		t.Fatalf("viewer password %q", res.ViewerPassword)
	}
	var roleID string
	for id, r := range f.objs["Role"] {
		if r["description"] != ViewerRole {
			continue
		}
		roleID = id
		perms := r["enabledPermissions"].(map[string]any)
		if len(perms) != len(stalwart.ViewerRolePermissions) {
			t.Fatalf("viewer role holds %d permissions, want %d", len(perms), len(stalwart.ViewerRolePermissions))
		}
		for p := range perms {
			if strings.HasSuffix(p, "Create") || strings.HasSuffix(p, "Update") || strings.HasSuffix(p, "Destroy") {
				t.Errorf("viewer role holds %s", p)
			}
		}
	}
	if roleID == "" {
		t.Fatal("no viewer role")
	}
	var parking string
	for id, d := range f.objs["Domain"] {
		if d["name"] == ParkingDomain {
			parking = id
		}
	}
	found := false
	for _, a := range f.objs["Account"] {
		if a["name"] != ViewerAccount {
			continue
		}
		found = true
		roles := a["roles"].(map[string]any)
		ids := roles["roleIds"].(map[string]any)
		if a["domainId"] != parking || roles["@type"] != "Custom" || len(ids) != 1 || ids[roleID] != true {
			t.Fatalf("viewer account %v", a)
		}
	}
	if !found {
		t.Fatal("no viewer account")
	}
	if ss := f.objs["SystemSettings"]["singleton"]; ss == nil || ss["includeSecrets"] != false {
		t.Fatalf("includeSecrets isn't pinned false: %v", ss)
	}
	rules := fmt.Sprint(p.AllowedEndpoints())
	if !strings.Contains(rules, "listener == 'admin-view' && remote_ip == '172.31.255.5'") {
		t.Fatalf("no admin-view rule: %s", rules)
	}
	// A second run keeps one viewer account (a new password, no create).
	res2 := run(t, f, p, false)
	n := 0
	for _, a := range f.objs["Account"] {
		if a["name"] == ViewerAccount {
			n++
		}
	}
	if n != 1 || res2.ViewerPassword == res.ViewerPassword {
		t.Fatalf("%d viewer accounts after a second run, password changed: %v", n, res2.ViewerPassword != res.ViewerPassword)
	}
	// ResetViewer on the bootstrapped store: a new password, nothing else.
	srv := httptest.NewServer(f)
	defer srv.Close()
	pw, err := ResetViewer(context.Background(), stalwart.New(srv.URL, stalwart.Basic("r", "p")))
	if err != nil || len(pw) < 40 {
		t.Fatalf("ResetViewer: %q %v", pw, err)
	}
	// No admin view rule without the proxy's address.
	if strings.Contains(fmt.Sprint(params().AllowedEndpoints()), "admin-view") {
		t.Fatal("admin-view rule without a ViewerIP")
	}
}

// A store from before the admin view: ResetViewer answers "" (the view
// stays unavailable) and writes nothing.
func TestResetViewerWithoutViewer(t *testing.T) {
	f := newFake()
	f.put("Domain", map[string]any{"name": ParkingDomain})
	srv := httptest.NewServer(f)
	defer srv.Close()
	pw, err := ResetViewer(context.Background(), stalwart.New(srv.URL, stalwart.Basic("r", "p")))
	if err != nil || pw != "" {
		t.Fatalf("ResetViewer: %q %v", pw, err)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "/set") {
			t.Fatalf("wrote %s", c)
		}
	}
}

// TestViewerPasswordNeverReachesViewer (security review N4, data flow):
// the passwords the plan sets (the viewer's, mailctl's) sit only in masked
// secret fields.
func TestViewerPasswordNeverReachesViewer(t *testing.T) {
	f := newFake()
	p := params()
	p.ViewerIP = netip.MustParseAddr("172.31.255.5")
	res := run(t, f, p, false)
	schema, err := os.ReadFile("../stalwart/testdata/schema-v1.1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	sf, _ := stalwart.SecretFieldNames(schema)
	seen := false
	for obj, objs := range f.objs {
		for _, o := range objs {
			if b, _ := json.Marshal(o); strings.Contains(string(b), res.ViewerPassword) {
				seen = true
			}
			if l := stalwart.ViewerSecretLeaks(obj, o, res.ViewerPassword, sf); len(l) > 0 {
				t.Errorf("the viewer password reaches the viewer: %v", l)
			}
		}
	}
	if !seen {
		t.Fatal("the viewer password was never stored: the check proves nothing")
	}
}
