// Package bootstrap applies Stalwart's base plan (contract §19.4) as the
// recovery admin, idempotently, and makes mailctl's own Stalwart identity:
// the role portcullis-mailctl, its account on the parking domain and its
// one API key. Every object, field and value it sends is in stalwart.Used
// (checked against the schema snapshot).
package bootstrap

import (
	"fmt"
	"github.com/portcullis/mailctl/internal/creds"
	"net/netip"

	"github.com/portcullis/mailctl/internal/stalwart"
)

// ParkingDomain holds removed and former accounts (M4; `.invalid` is
// refused by Stalwart, Task 2). Never in DNS or a mail set.
const ParkingDomain = "portcullis-former.internal"

// Names of the objects the base plan owns.
const (
	MailctlRole    = "portcullis-mailctl"
	UserRole       = "portcullis-mail-user"
	MailctlAccount = "portcullis-mailctl"
	APIKeyName     = "mailctl"
	// The read-only mail admin view (contract §19.13): its role and its
	// account on the parking domain, whose password only the template's
	// admin-view service holds.
	ViewerRole    = "portcullis-viewer"
	ViewerAccount = "portcullis-viewer"
	// AdminViewPort is the admin view's TLS listener: Stalwart serves its
	// web admin's sign-in only over TLS and only to a trusted host
	// (STALWART_PUBLIC_URL), so the admin-view proxy dials it here.
	AdminViewPort     = 8443
	AdminViewListener = "admin-view"
	// WebUIBundle is the web admin bundle, pinned in the mailctl image and
	// copied with mailctl into mailctl_bin (never downloaded at run time).
	WebUIBundle = "/portcullis/bin/webui.zip"
	SMTPPort    = 10025 // the MX listener (host port 25)
	MgmtPort    = 8080  // the management listener (JMAP / API)
	TLSDir      = "/run/portcullis/mail/tls"
	// The slot's files, mounted by the Hub's override at a fixed path
	// into the gated services (contract §19.1).
	SlotDir       = "/run/portcullis/mail/slot"
	MetricsSecret = SlotDir + "/metrics-secret"
	RelaySecret   = SlotDir + "/relay-password"
	RulesPath     = "/spam-filter-rules.json.gz"
)

// Sieve scripts selected by the RCPT and DATA stage expressions (trusted
// system scripts; Task 2: an expression alone can't refuse at RCPT).
const (
	ScriptParked = "parked-reject"
	ScriptList   = "list-reject"
	ScriptFrom   = "from-check"
)

// Lookup namespaces mailctl maintains (MemoryLookupKey, M10).
const (
	NSListMembersOnly = "list-members-only"
	NSListPosters     = "list-posters"
)

// Relay is the optional smarthost.
type Relay struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
}

// Params is everything the base plan depends on.
type Params struct {
	Hostname      string     // MAIL_HOSTNAME
	PrimaryDomain string     // the domain of every login (Stalwart's default domain)
	MailctlIP     netip.Addr // mailctl's portcullis-mail address (access rule, API key)
	ResolverIP    netip.Addr // mail-resolver
	ResolverPort  int
	RulesURL      string // http://<mailctl ip>:8082/spam-filter-rules.json.gz
	ClientIP      string // preserved | rewritten
	Relay         *Relay
	MetricsUser   string
	HTTPLookups   []map[string]any // the spam rules' HttpLookups (created disabled)
	LocalNetworks []string
	// LANOnly: submission_lan_only (the SASL rule admits only the
	// Local networks; loopback only with rewritten client addresses).
	LANOnly bool
	// ViewerIP is the admin-view proxy's internal address (contract
	// §19.13): the only client the admin-view listener answers. Invalid =
	// no admin view rule.
	ViewerIP netip.Addr
}

// saslNets: the Local networks the SASL rule admits (none with rewritten
// client addresses: loopback only, as the runner's LocalNets).
func (p Params) saslNets() []string {
	if p.ClientIP == "rewritten" {
		return nil
	}
	return p.LocalNetworks
}

func set(vals ...string) map[string]bool {
	m := make(map[string]bool, len(vals))
	for _, v := range vals {
		m[v] = true
	}
	return m
}

// expr builds an x:Expression: [if, then] pairs, then the else value.
func expr(els string, pairs ...[2]string) map[string]any {
	match := map[string]any{}
	for i, p := range pairs {
		match[fmt.Sprint(i)] = map[string]any{"if": p[0], "then": p[1]}
	}
	return map[string]any{"match": match, "else": els}
}

func list(items ...map[string]any) map[string]any {
	m := map[string]any{}
	for i, it := range items {
		m[fmt.Sprint(i)] = it
	}
	return m
}

func file(path string) map[string]any { return map[string]any{"@type": "File", "filePath": path} }

// on25 is true only on the MX listener: every stock `local_port == 25`
// default is rewritten for the 10025 listener (Task 2: otherwise port 25
// behaves as submission).
var on25 = fmt.Sprintf("local_port == %d", SMTPPort)

func on25Bool() map[string]any { return expr("false", [2]string{on25, "true"}) }

// Singleton is an update of a singleton object.
type Singleton struct {
	Object string
	Patch  map[string]any
}

// Named is a collection object the plan owns by a key field.
type Named struct {
	Object string
	Key    string // the identifying field ("name", "description", "@type", "namespace")
	Want   []map[string]any
	// DestroyOthers: objects of this type the plan doesn't name are destroyed.
	DestroyOthers bool
	// Immutable fields are sent on create only.
	Immutable []string
}

// listeners are the six (Global Constraints); every other one is destroyed.
func (p Params) listeners() Named {
	l := func(name, proto string, tls, implicit bool, binds ...string) map[string]any {
		return map[string]any{"name": name, "protocol": proto, "bind": set(binds...), "useTls": tls, "implicitTls": implicit}
	}
	return Named{Object: "NetworkListener", Key: "name", DestroyOthers: true, Immutable: []string{"name"}, Want: []map[string]any{
		l("smtp", "smtp", true, false, "[::]:10025"),
		l("submissions", "smtp", true, true, "[::]:10465"),
		l("submission", "smtp", true, false, "[::]:10587"),
		l("imaps", "imap", true, true, "[::]:10993"),
		// The wildcard (Ruling T17-b): the real server answers the adapter
		// on the template's internal network and the bootstrap job's server
		// its own job over loopback; the access rule admits only the
		// adapter's address off loopback (loopback bypasses it: only
		// Stalwart runs in its container), and the network isolation is the
		// real control.
		l("management", "http", false, false, fmt.Sprintf("[::]:%d", MgmtPort)),
		// portcullis-metrics-mail is unpinned, so the metrics listener binds
		// every address; the access rule answers it only /metrics/prometheus,
		// with the scrape password.
		l("metrics", "http", false, false, "[::]:9180"),
		// The read-only admin view (contract §19.13): TLS with the mail
		// certificate, answered only to the admin-view proxy's address.
		l(AdminViewListener, "http", true, true, fmt.Sprintf("[::]:%d", AdminViewPort)),
	}}
}

// AllowedEndpoints is the management listener's access rule (M12, Task 2
// tweak: rule 0 also requires the management listener). Loopback bypasses
// it; an expression error answers 200, so the network isolation is the
// real control.
func (p Params) AllowedEndpoints() map[string]any {
	ip := p.MailctlIP.String()
	rules := [][2]string{
		{fmt.Sprintf("listener == 'management' && remote_ip == '%s' && (starts_with(path, '/jmap') || starts_with(path, '/api') || path == '/.well-known/jmap')", ip), "200"},
		{"listener == 'metrics' && path == '/metrics/prometheus'", "200"},
	}
	if p.ViewerIP.IsValid() {
		// The admin view (contract §19.13): only the proxy's address, only
		// the web admin's paths (the proxy filters them again).
		rules = append(rules, [2]string{fmt.Sprintf("listener == '%s' && remote_ip == '%s' && (%s)", AdminViewListener, p.ViewerIP, adminViewPaths), "200"})
	}
	return expr("404", rules...)
}

// adminViewPaths are the paths the admin-view listener answers: the web
// admin, its sign-in and token endpoints, its reads.
const adminViewPaths = "starts_with(path, '/admin') || path == '/login' || starts_with(path, '/logo') || starts_with(path, '/api/') || starts_with(path, '/auth/') || starts_with(path, '/jmap') || starts_with(path, '/.well-known/o')"

// WebUIApplication is the web admin's settings (contract §19.13): served
// only at /admin (never the /account self-service: a mail password opens
// no web interface, P11), from the bundle pinned in the mailctl image.
func WebUIApplication() map[string]any {
	return map[string]any{"enable": true, "urlPrefix": set("/admin"), "resourceUrl": "file://" + WebUIBundle}
}

func (p Params) senderAuth() map[string]any {
	relaxed25 := expr("disable", [2]string{on25, "relaxed"})
	sa := map[string]any{
		"dkimVerify":      expr("disable", [2]string{on25, "relaxed"}),
		"arcVerify":       relaxed25,
		"dmarcVerify":     relaxed25,
		"spfEhloVerify":   relaxed25,
		"spfFromVerify":   relaxed25,
		"reverseIpVerify": relaxed25,
	}
	if p.ClientIP == "rewritten" {
		for k, v := range DegradedSenderAuth() {
			sa[k] = v
		}
	}
	return sa
}

// DegradedSenderAuth is M9's sender authentication for rewritten client
// addresses (rootless Podman): every client seems to come from one
// gateway address, so SPF (HELO and MAIL FROM) and iprev would judge the
// gateway: off. DMARC stays relaxed (it evaluates DKIM alignment; relaxed
// never rejects on a DMARC failure), DKIM and ARC as normal. The IP-type
// DNSBLs are off too (reconcile), and the ban rates (DegradedSecurity).
func DegradedSenderAuth() map[string]any {
	off := expr("disable")
	return map[string]any{"spfEhloVerify": off, "spfFromVerify": off, "reverseIpVerify": off,
		"dmarcVerify": expr("disable", [2]string{on25, "relaxed"})}
}

// NormalSecurity is Stalwart v1.1.0's default ban rates (the schema
// snapshot's x:Security defaults), written explicitly so leaving degraded
// mode restores the bans.
func NormalSecurity() map[string]any {
	day := 86400000
	r := func(n int) map[string]any { return map[string]any{"count": n, "period": day} }
	return map[string]any{"authBanRate": r(100), "abuseBanRate": r(35), "loiterBanRate": r(150), "scanBanRate": r(30)}
}

// DegradedSecurity: no automatic bans with rewritten client addresses —
// every client is the gateway, so a ban would lock everyone out (the
// server would ban itself). Brute force is still bounded by the auth
// throttles and the per-password allowedIps.
func DegradedSecurity() map[string]any {
	return map[string]any{"authBanRate": nil, "abuseBanRate": nil, "loiterBanRate": nil, "scanBanRate": nil}
}

// Spam allow / block lists (contract §19.8) by domain or address, in
// mailctl's own lookup namespaces (the stock trusted-domains list holds
// the rules' defaults). Allow needs DMARC to pass (an unauthenticated From
// is never trusted) and reuses the stock TRUSTED_DOMAIN score; block
// reuses BLOCKED_DOMAIN (reject).
const (
	NSSpamAllow = "portcullis-allow"
	NSSpamBlock = "portcullis-block"
)

func spamRules() Named {
	from := func(ns string) string {
		return fmt.Sprintf("(key_exists('%s', from.domain) || key_exists('%s', from.local + '@' + from.domain))", ns, ns)
	}
	rule := func(name, cond, tag string) map[string]any {
		return map[string]any{"@type": "Any", "name": name, "enable": true, "priority": 16,
			"description": "Portcullis (mailctl base plan)",
			"condition":   expr("false", [2]string{cond, "'" + tag + "'"})}
	}
	return Named{Object: "SpamRule", Key: "name", Immutable: []string{"name"}, Want: []map[string]any{
		rule("PORTCULLIS_ALLOW", "$DMARC_POLICY_ALLOW && "+from(NSSpamAllow), "TRUSTED_DOMAIN"),
		rule("PORTCULLIS_BLOCK", from(NSSpamBlock), "BLOCKED_DOMAIN"),
	}}
}

// rcptScript selects the trusted Sieve script that refuses at RCPT: the
// parking domain (a parked account would accept and bounce later, Task 2)
// and members-only lists for anyone who isn't a member (M10).
func rcptScript() map[string]any {
	return expr("false",
		[2]string{fmt.Sprintf("rcpt_domain == '%s'", ParkingDomain), "'" + ScriptParked + "'"},
		[2]string{fmt.Sprintf("key_exists('%s', rcpt) && !key_exists('%s', rcpt + '|' + authenticated_as)", NSListMembersOnly, NSListPosters), "'" + ScriptList + "'"},
	)
}

func sieveScripts() Named {
	s := func(name, contents string) map[string]any {
		return map[string]any{"name": name, "contents": contents, "isActive": true, "description": "Portcullis (mailctl base plan)"}
	}
	return Named{Object: "SieveSystemScript", Key: "name", Want: []map[string]any{
		s(ScriptParked, "require [\"reject\"];\nreject \"550 5.1.1 Mailbox does not exist\";\n"),
		s(ScriptList, "require [\"reject\"];\nreject \"550 5.7.1 only members may post\";\n"),
		// P30 (+ security ruling): an authenticated sender's message has
		// exactly one From: header holding exactly one address, equal to the
		// envelope sender (which mustMatchSender ties to the login's
		// addresses); an empty envelope sender is refused. :count counts
		// every From: header / every address in them (RFC 5231).
		s(ScriptFrom, FromCheckSieve),
	}}
}

// FromCheckSieve is the DATA-stage script for authenticated sessions.
const FromCheckSieve = `require ["envelope", "variables", "reject", "relational", "comparator-i;ascii-numeric"];
if not envelope :matches "from" "?*" {
  reject "550 5.7.1 an authenticated message needs a sender address";
  stop;
}
if header :count "ne" :comparator "i;ascii-numeric" "from" "1" {
  reject "550 5.7.1 the message must have exactly one From: header";
  stop;
}
if address :count "ne" :comparator "i;ascii-numeric" :all "from" "1" {
  reject "550 5.7.1 the From: header must hold exactly one address";
  stop;
}
if envelope :matches "from" "*" { set "ef" "${1}"; }
if not address :all :is "from" "${ef}" {
  reject "550 5.7.1 the From: header must be your own address";
  stop;
}
`

// PlaceholderHostname is defaultHostname before any document (Ruling
// T17-d: Stalwart 1.1 requires one): a name on the parking domain, never
// in DNS; ApplyDoc replaces it with the document's mail_hostname.
const PlaceholderHostname = "mail." + ParkingDomain

// systemSettings: the document's host name, else the placeholder (the
// bootstrap job's first run has no document; ApplyDoc writes the real one).
func (p Params) systemSettings() map[string]any {
	h := p.Hostname
	if h == "" {
		h = PlaceholderHostname
	}
	return map[string]any{"maxBufferedMemory": 134217728, "defaultHostname": h}
}

func (p Params) domains() []map[string]any {
	d := []map[string]any{{"name": ParkingDomain}}
	if p.PrimaryDomain != "" {
		d = append(d, map[string]any{"name": p.PrimaryDomain})
	}
	return d
}

// Singletons are the settings the plan sets on every run.
func (p Params) Singletons() []Singleton {
	tlsStrategy := "'default'"
	route := "'mx'"
	if p.Relay != nil {
		tlsStrategy, route = "'relay-strict'", "'relay'"
	}
	ss := []Singleton{
		{"SystemSettings", p.systemSettings()},
		{"Cache", map[string]any{"messagesLarge": 0, "groupwareLarge": 0, "messages": 67108864}},
		{"DnsResolver", map[string]any{"@type": "Custom", "servers": list(
			map[string]any{"protocol": "udp", "address": p.ResolverIP.String(), "port": p.ResolverPort},
			map[string]any{"protocol": "tcp", "address": p.ResolverIP.String(), "port": p.ResolverPort},
		)}},
		{"Http", map[string]any{"allowedEndpoints": p.AllowedEndpoints()}},
		{"Metrics", map[string]any{"prometheus": map[string]any{"@type": "Enabled", "authUsername": p.MetricsUser, "authSecret": file(MetricsSecret)}}},
		{"MtaStageAuth", map[string]any{
			"saslMechanisms":  creds.SASLExpression(p.LANOnly, p.saslNets(), SMTPPort),
			"require":         expr(fmt.Sprintf("local_port != %d", SMTPPort)),
			"mustMatchSender": expr("true"),
		}},
		{"MtaStageEhlo", map[string]any{"rejectNonFqdn": on25Bool()}},
		{"MtaStageRcpt", map[string]any{
			// No IP-based trust: only an authenticated session relays.
			"allowRelaying": expr("!is_empty(authenticated_as)"),
			"maxRecipients": expr("100"),
			"script":        rcptScript(),
		}},
		{"MtaStageData", map[string]any{
			"addAuthResultsHeader": on25Bool(), "addDateHeader": on25Bool(), "addMessageIdHeader": on25Bool(),
			"addReceivedHeader": on25Bool(), "addReceivedSpfHeader": on25Bool(), "addReturnPathHeader": on25Bool(),
			"script": expr("false", [2]string{"!is_empty(authenticated_as)", "'" + ScriptFrom + "'"}),
		}},
		{"SenderAuth", p.senderAuth()},
		{"MtaOutboundStrategy", map[string]any{
			"route": expr(route, [2]string{"is_local_domain(rcpt_domain)", "'local'"}),
			// Never the stock invalid-tls fallback: a TLS failure stays one.
			"tls": expr(tlsStrategy),
		}},
		{"SpamSettings", map[string]any{
			"enable": true, "scoreSpam": 5, "scoreReject": 15, "scoreDiscard": 0, "greylistFor": nil,
			"spamFilterRulesUrl": p.RulesURL,
		}},
		{"SpamAi", map[string]any{"@type": "Disable"}},
		{"SpamPyzor", map[string]any{"enable": false}},
		{"ReportSettings", map[string]any{
			"inboundReportAddresses":  set("dmarc-reports@*", "tls-reports@*"),
			"inboundReportForwarding": false,
		}},
	}
	// Always managed: every switch between the modes rewrites it.
	if p.ClientIP == "rewritten" {
		ss = append(ss, Singleton{"Security", DegradedSecurity()})
	} else {
		ss = append(ss, Singleton{"Security", NormalSecurity()})
	}
	return ss
}

// Collections the plan owns by name (created in this order).
func (p Params) Collections() []Named {
	strategies := []map[string]any{{"name": "default", "dane": "optional", "mtaSts": "optional", "startTls": "optional", "allowInvalidCerts": false}}
	// The plan makes the routes, so Stalwart inserts none of its defaults
	// (inserted only while there are none): local delivery is ours too.
	routes := []map[string]any{{"@type": "Mx", "name": "mx", "ipLookupStrategy": "v4Only"}, {"@type": "Local", "name": "local"}}
	if p.Relay != nil {
		strategies = append(strategies, map[string]any{"name": "relay-strict", "dane": "optional", "mtaSts": "optional", "startTls": "require", "allowInvalidCerts": false})
		r := map[string]any{"@type": "Relay", "name": "relay", "host": p.Relay.Host, "port": p.Relay.Port, "implicitTls": p.Relay.Port == 465, "protocol": "smtp", "allowInvalidCerts": false}
		if p.Relay.Username != "" {
			r["authUsername"], r["authSecret"] = p.Relay.Username, file(RelaySecret)
		} else {
			r["authUsername"], r["authSecret"] = nil, map[string]any{"@type": "None"}
		}
		routes = append(routes, r)
	}
	lookups := make([]map[string]any, 0, len(p.HTTPLookups))
	for _, l := range p.HTTPLookups {
		c := map[string]any{}
		for k, v := range l {
			c[k] = v
		}
		c["enable"] = false
		lookups = append(lookups, c)
	}
	return []Named{
		p.listeners(),
		{Object: "Tracer", Key: "@type", DestroyOthers: true, Want: []map[string]any{{"@type": "Stdout", "ansi": false, "enable": true, "level": "info"}}},
		sieveScripts(),
		spamRules(),
		{Object: "MtaTlsStrategy", Key: "name", Immutable: []string{"name"}, Want: strategies},
		{Object: "MtaRoute", Key: "name", Immutable: []string{"name"}, Want: routes},
		// The spam rules' external feeds (openphish, phishtank, …): made
		// before the first import, disabled; an import keeps the local
		// `enable` (Task 2). mailctl serve re-checks them.
		{Object: "HttpLookup", Key: "namespace", Immutable: []string{"namespace"}, Want: lookups},
		{Object: "Role", Key: "description", Want: []map[string]any{
			{"description": MailctlRole, "enabledPermissions": set(stalwart.MailctlRolePermissions...)},
			{"description": UserRole, "enabledPermissions": set(stalwart.MailPasswordPermissions...)},
			{"description": ViewerRole, "enabledPermissions": set(stalwart.ViewerRolePermissions...)},
		}},
		{Object: "Domain", Key: "name", Immutable: []string{"name"}, Want: p.domains()},
	}
}

// manual is every domain's management (no ACME, DNS or DKIM automation in
// Stalwart: Portcullis owns them).
var manual = map[string]any{
	"certificateManagement": map[string]any{"@type": "Manual"},
	"dnsManagement":         map[string]any{"@type": "Manual"},
	"dkimManagement":        map[string]any{"@type": "Manual"},
}

// RoutePlanText is a one-line summary for logs (no secrets).
func (p Params) RoutePlanText() string {
	if p.Relay == nil {
		return "direct delivery (mx)"
	}
	return "relay " + p.Relay.Host + ":" + fmt.Sprint(p.Relay.Port)
}

func init() {
	// Register every object, field and variant the plan sends.
	p := Params{Hostname: "h.example", PrimaryDomain: "example.com", MailctlIP: netip.MustParseAddr("192.0.2.3"),
		ResolverIP: netip.MustParseAddr("192.0.2.4"), ResolverPort: 5353, ClientIP: "rewritten",
		Relay: &Relay{Host: "r.example", Port: 465, Username: "u"}, MetricsUser: "prometheus",
		HTTPLookups: []map[string]any{{"namespace": "x", "url": "https://x.example", "format": map[string]any{"@type": "List"}}}}
	stalwart.Used = append(stalwart.Used, stalwart.Use{Object: "x:SystemSettings", Field: "defaultHostname"})
	reg := func(obj string, m map[string]any) {
		variant := ""
		if t, ok := m["@type"].(string); ok {
			variant = t
			stalwart.Used = append(stalwart.Used, stalwart.Use{Object: "x:" + obj, Variant: t})
		}
		for k := range m {
			if k == "@type" {
				continue
			}
			stalwart.Used = append(stalwart.Used, stalwart.Use{Object: "x:" + obj, Variant: variant, Field: k})
		}
	}
	for _, s := range p.Singletons() {
		reg(s.Object, s.Patch)
	}
	for _, n := range p.Collections() {
		for _, w := range n.Want {
			reg(n.Object, w)
		}
	}
	reg("Domain", manual)
	reg("Certificate", map[string]any{"certificate": nil, "privateKey": nil})
	reg("SystemSettings", map[string]any{"defaultCertificateId": nil, "defaultDomainId": nil})
	reg("Authentication", map[string]any{"defaultUserRoleIds": nil})
	reg("Application", WebUIApplication())
	reg("Asn", map[string]any{"@type": "Resource", "asnUrls": nil, "geoUrls": nil})
	stalwart.Used = append(stalwart.Used, stalwart.Use{Object: "x:Asn", Variant: "Disabled"})
	reg("Account", map[string]any{"@type": "User", "name": nil, "domainId": nil, "description": nil, "credentials": nil, "roles": nil})
	reg("ApiKey", map[string]any{"description": nil, "permissions": nil, "allowedIps": nil})
	for _, u := range []stalwart.Use{
		{Object: "x:AcmeProvider"},
		{Object: "x:UserRoles", Variant: "Custom", Field: "roleIds"},
		{Object: "x:CredentialPermissions", Variant: "Inherit"},
		{Object: "x:PublicText", Variant: "File", Field: "filePath"},
		{Object: "x:SecretText", Variant: "File", Field: "filePath"},
		{Object: "x:SecretKeyOptional", Variant: "File", Field: "filePath"},
		{Object: "x:SecretKeyOptional", Variant: "None"},
		{Object: "x:MetricsPrometheus", Variant: "Enabled", Field: "authUsername"},
		{Object: "x:MetricsPrometheus", Variant: "Enabled", Field: "authSecret"},
		{Object: "x:DnsCustomResolver", Field: "protocol"}, {Object: "x:DnsCustomResolver", Field: "address"}, {Object: "x:DnsCustomResolver", Field: "port"},
		{Object: "x:CertificateManagement", Variant: "Manual"}, {Object: "x:DnsManagement", Variant: "Manual"}, {Object: "x:DkimManagement", Variant: "Manual"},
		{Object: "x:Expression", Field: "match"}, {Object: "x:Expression", Field: "else"},
		{Object: "x:ExpressionMatch", Field: "if"}, {Object: "x:ExpressionMatch", Field: "then"},
		{Enum: "NetworkListenerProtocol", Value: "smtp"}, {Enum: "NetworkListenerProtocol", Value: "imap"}, {Enum: "NetworkListenerProtocol", Value: "http"},
		{Enum: "MtaRequiredOrOptional", Value: "optional"}, {Enum: "MtaRequiredOrOptional", Value: "require"},
		{Enum: "MtaIpStrategy", Value: "v4Only"}, {Enum: "DnsResolverProtocol", Value: "udp"}, {Enum: "DnsResolverProtocol", Value: "tcp"},
		{Enum: "TracingLevel", Value: "info"},
		{Enum: "ActionType", Value: "ReloadTlsCertificates"},
		{Object: "x:Action", Variant: "ReloadTlsCertificates"},
	} {
		stalwart.Used = append(stalwart.Used, u)
	}
}
