package main

import (
	"crypto/x509"
	"embed"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	vault "github.com/hashicorp/vault/api"
)

//go:embed web/*
var webFS embed.FS

var templates *template.Template

type Config struct {
	VaultAddr string
	// vault holds the AppRole login state. It is a pointer so that copies of
	// Config (Server embeds one by value) share the same cached token.
	vault        *vaultAuth
	LDAPUrl      string
	LDAPBaseDN   string
	LDAPBindDN   string
	LDAPBindPass string
	Domain       string
	ListenAddr   string
	CertTTL      string
	PKIRole      string
}

type User struct {
	Username  string `json:"username"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	DN        string `json:"dn"`
}

type CertInfo struct {
	Username  string    `json:"username"`
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
	Issuer    string    `json:"issuer"`
}

type SignResponse struct {
	Certificate string `json:"certificate"`
	CAChain     string `json:"caChain"`
	Serial      string `json:"serial"`
	Expiry      string `json:"expiry"`
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func loadConfig() Config {
	vaultAddr := envOr("VAULT_ADDR", "http://vault:8200")
	return Config{
		VaultAddr: vaultAddr,
		vault: newVaultAuth(
			vaultAddr,
			envOr("VAULT_APPROLE_MOUNT", "approle"),
			envOr("VAULT_ROLE_ID_FILE", "/run/secrets/portcullis-enroll/role-id"),
			envOr("VAULT_SECRET_ID_FILE", "/run/secrets/portcullis-enroll/secret-id"),
		),
		LDAPUrl:      envOr("LLDAP_URL", "ldap://lldap:3890"),
		LDAPBaseDN:   envOr("LLDAP_BASE_DN", "dc=portcullis,dc=local"),
		LDAPBindDN:   envOr("LLDAP_BIND_DN", "uid=admin,ou=people,dc=portcullis,dc=local"),
		LDAPBindPass: envOr("LLDAP_BIND_PASSWORD", "changeme"),
		Domain:       envOr("PORTCULLIS_DOMAIN", "portcullis.local"),
		ListenAddr:   envOr("LISTEN_ADDR", ":8443"),
		CertTTL:      envOr("CERT_TTL", "24h"),
		PKIRole:      envOr("PKI_ROLE", "client-cert"),
	}
}

// LDAP operations

func (cfg *Config) ldapConn() (*ldap.Conn, error) {
	l, err := ldap.DialURL(cfg.LDAPUrl)
	if err != nil {
		return nil, fmt.Errorf("ldap dial: %w", err)
	}
	err = l.Bind(cfg.LDAPBindDN, cfg.LDAPBindPass)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("ldap bind: %w", err)
	}
	return l, nil
}

func (cfg *Config) listUsers() ([]User, error) {
	l, err := cfg.ldapConn()
	if err != nil {
		return nil, err
	}
	defer l.Close()

	result, err := l.Search(ldap.NewSearchRequest(
		"ou=people,"+cfg.LDAPBaseDN,
		ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=person)",
		[]string{"uid", "mail", "givenName", "sn"},
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("ldap search: %w", err)
	}

	users := make([]User, 0, len(result.Entries))
	for _, entry := range result.Entries {
		users = append(users, User{
			Username:  entry.GetAttributeValue("uid"),
			Email:     entry.GetAttributeValue("mail"),
			FirstName: entry.GetAttributeValue("givenName"),
			LastName:  entry.GetAttributeValue("sn"),
			DN:        entry.DN,
		})
	}
	return users, nil
}

func (cfg *Config) getUser(username string) (*User, error) {
	l, err := cfg.ldapConn()
	if err != nil {
		return nil, err
	}
	defer l.Close()

	result, err := l.Search(ldap.NewSearchRequest(
		"ou=people,"+cfg.LDAPBaseDN,
		ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 1, 0, false,
		fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(username)),
		[]string{"uid", "mail", "givenName", "sn"},
		nil,
	))
	if err != nil {
		return nil, err
	}
	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("user not found: %s", username)
	}

	entry := result.Entries[0]
	return &User{
		Username:  entry.GetAttributeValue("uid"),
		Email:     entry.GetAttributeValue("mail"),
		FirstName: entry.GetAttributeValue("givenName"),
		LastName:  entry.GetAttributeValue("sn"),
		DN:        entry.DN,
	}, nil
}

// Vault authentication
//
// enroll authenticates with a least-privilege AppRole (policy
// vault/policies/enroll.hcl, created by ./portcullis vault init): it can only
// sign with the client-cert role and read/list issued certs. There is no
// static token and no fallback. Tokens are short-lived (1h); vaultAuth logs
// in again shortly before expiry, and immediately when Vault answers 403
// (token revoked, secret-id rotated, Vault re-initialised), so the token
// can never silently expire. The role-id / secret-id files are re-read on
// every login, so rotating them needs no restart.

const tokenRefreshMargin = 5 * time.Minute

type vaultAuth struct {
	addr         string
	mount        string
	roleIDFile   string
	secretIDFile string
	now          func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

func newVaultAuth(addr, mount, roleIDFile, secretIDFile string) *vaultAuth {
	return &vaultAuth{addr: addr, mount: mount, roleIDFile: roleIDFile, secretIDFile: secretIDFile, now: time.Now}
}

func readSecretFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return v, nil
}

func (a *vaultAuth) newClient() (*vault.Client, error) {
	c, err := vault.NewClient(&vault.Config{Address: a.addr})
	if err != nil {
		return nil, err
	}
	// NewClient picks up VAULT_TOKEN from the environment; never use it.
	c.ClearToken()
	return c, nil
}

// login performs an AppRole login. Caller holds a.mu.
func (a *vaultAuth) login(c *vault.Client) error {
	roleID, err := readSecretFile(a.roleIDFile)
	if err != nil {
		return fmt.Errorf("vault approle role-id: %w (run ./portcullis vault init)", err)
	}
	secretID, err := readSecretFile(a.secretIDFile)
	if err != nil {
		return fmt.Errorf("vault approle secret-id: %w (run ./portcullis vault init)", err)
	}
	secret, err := c.Logical().Write("auth/"+a.mount+"/login", map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil {
		return fmt.Errorf("vault approle login: %w", err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return errors.New("vault approle login: response has no token")
	}
	ttl := time.Duration(secret.Auth.LeaseDuration) * time.Second
	if ttl <= 0 {
		ttl = time.Hour // non-expiring token (unexpected): still re-login hourly
	}
	a.token = secret.Auth.ClientToken
	a.expires = a.now().Add(ttl)
	return nil
}

// client returns a Vault client carrying a valid token, logging in first
// if there is none, it is about to expire, or force is set.
func (a *vaultAuth) client(force bool) (*vault.Client, error) {
	c, err := a.newClient()
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if force || a.token == "" || !a.now().Before(a.expires.Add(-tokenRefreshMargin)) {
		if err := a.login(c); err != nil {
			a.token = ""
			return nil, err
		}
	}
	c.SetToken(a.token)
	return c, nil
}

// do runs fn with an authenticated client, retrying once with a fresh
// login if Vault rejects the cached token with 403.
func (a *vaultAuth) do(fn func(*vault.Client) error) error {
	c, err := a.client(false)
	if err != nil {
		return err
	}
	err = fn(c)
	var re *vault.ResponseError
	if errors.As(err, &re) && re.StatusCode == http.StatusForbidden {
		log.Printf("vault: 403 with cached token, logging in again")
		if c, err = a.client(true); err != nil {
			return err
		}
		err = fn(c)
	}
	return err
}

// Vault PKI operations

func (cfg *Config) signCSR(username, email, csr string) (*SignResponse, error) {
	var secret *vault.Secret
	err := cfg.vault.do(func(vc *vault.Client) error {
		var err error
		secret, err = vc.Logical().Write("pki_int/sign/"+cfg.PKIRole, map[string]interface{}{
			"csr":         csr,
			"common_name": username,
			"ttl":         cfg.CertTTL,
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("vault sign: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, errors.New("vault sign: empty response")
	}
	cert, ok := secret.Data["certificate"].(string)
	if !ok || cert == "" {
		return nil, errors.New("vault sign: response missing certificate")
	}
	serial, _ := secret.Data["serial_number"].(string)

	var caChain string
	if chain, ok := secret.Data["ca_chain"].([]interface{}); ok {
		parts := make([]string, 0, len(chain))
		for _, c := range chain {
			if pemStr, ok := c.(string); ok {
				parts = append(parts, pemStr)
			}
		}
		caChain = strings.Join(parts, "\n")
	}

	// Parse cert to get expiry
	block, _ := pem.Decode([]byte(cert))
	var expiry string
	if block != nil {
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			expiry = parsed.NotAfter.Format(time.RFC3339)
		}
	}

	return &SignResponse{
		Certificate: cert,
		CAChain:     caChain,
		Serial:      serial,
		Expiry:      expiry,
	}, nil
}

func (cfg *Config) listCerts() ([]CertInfo, error) {
	var certs []CertInfo
	err := cfg.vault.do(func(vc *vault.Client) error {
		var err error
		certs, err = listCertsWith(vc)
		return err
	})
	return certs, err
}

func listCertsWith(vc *vault.Client) ([]CertInfo, error) {
	secret, err := vc.Logical().List("pki_int/certs")
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data["keys"] == nil {
		return []CertInfo{}, nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return nil, errors.New("vault list: unexpected response shape")
	}
	certs := make([]CertInfo, 0, len(keys))

	for _, k := range keys {
		serial, ok := k.(string)
		if !ok {
			continue
		}
		certSecret, err := vc.Logical().Read("pki_int/cert/" + serial)
		if err != nil || certSecret == nil || certSecret.Data == nil {
			continue
		}

		certPEM, ok := certSecret.Data["certificate"].(string)
		if !ok {
			continue
		}
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			continue
		}

		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		// Only include client certs (not CA or server certs)
		if !parsed.IsCA && parsed.Subject.CommonName != "" {
			certs = append(certs, CertInfo{
				Username:  parsed.Subject.CommonName,
				Serial:    serial,
				NotBefore: parsed.NotBefore,
				NotAfter:  parsed.NotAfter,
				Issuer:    parsed.Issuer.CommonName,
			})
		}
	}
	return certs, nil
}

// Look up LLDAP username by email address
func (cfg *Config) usernameByEmail(email string) string {
	l, err := cfg.ldapConn()
	if err != nil {
		return email
	}
	defer l.Close()
	result, err := l.Search(ldap.NewSearchRequest(
		"ou=people,"+cfg.LDAPBaseDN,
		ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 1, 5, false,
		fmt.Sprintf("(mail=%s)", ldap.EscapeFilter(email)),
		[]string{"uid"},
		nil,
	))
	if err != nil || len(result.Entries) == 0 {
		return email
	}
	if uid := result.Entries[0].GetAttributeValue("uid"); uid != "" {
		return uid
	}
	return email
}

// Extract authenticated user from forward-auth header or Traefik's client cert header
func (s *Server) authenticatedUser(r *http.Request) string {
	// Check forward-auth / OIDC user first (returns email)
	if email := r.Header.Get("X-Forwarded-User"); email != "" {
		return s.cfg.usernameByEmail(email)
	}
	info := r.Header.Get("X-Forwarded-Tls-Client-Cert-Info")
	if info == "" {
		return ""
	}
	// Traefik URL-encodes the info header
	decoded, err := url.QueryUnescape(info)
	if err != nil {
		return ""
	}
	// Extract CN from Subject="CN=username,..."
	for _, part := range strings.Split(decoded, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "Subject=\"") {
			subject := strings.TrimPrefix(part, "Subject=\"")
			subject = strings.TrimSuffix(subject, "\"")
			for _, attr := range strings.Split(subject, ",") {
				attr = strings.TrimSpace(attr)
				if strings.HasPrefix(attr, "CN=") {
					return strings.TrimPrefix(attr, "CN=")
				}
			}
		}
	}
	return ""
}

// HTTP handlers

type Server struct {
	cfg Config
}

const adminGroup = "lldap_admin"

// isAdmin reports whether the request carries the lldap_admin group.
// X-Auth-Request-Groups is set by Traefik from the forward-auth response
// (authResponseHeaders), which overwrites any client-supplied value.
func isAdmin(r *http.Request) bool {
	for _, v := range r.Header.Values("X-Auth-Request-Groups") {
		for _, g := range strings.Split(v, ",") {
			if strings.TrimSpace(g) == adminGroup {
				return true
			}
		}
	}
	return false
}

var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

// validateCSR parses and verifies a PEM CSR and checks that its identity
// matches the enrolling user: Subject must be exactly CN=<username>,
// optionally with emailAddress=<user's directory email>. SANs are only
// allowed if they are that same email. Returns a client-safe error.
func validateCSR(csrPEM, username, email string) error {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return errors.New("csr is not a PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return errors.New("csr could not be parsed")
	}
	if err := csr.CheckSignature(); err != nil {
		return errors.New("csr signature is invalid")
	}
	if csr.Subject.CommonName != username {
		return errors.New("csr common name does not match username")
	}
	sawCN := false
	for _, n := range csr.Subject.Names {
		switch {
		case n.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 3}):
			if sawCN {
				return errors.New("csr has multiple common names")
			}
			sawCN = true
		case n.Type.Equal(oidEmailAddress):
			v, _ := n.Value.(string)
			if email == "" || !strings.EqualFold(v, email) {
				return errors.New("csr emailAddress does not match the user's email")
			}
		default:
			return fmt.Errorf("csr subject has unexpected attribute %s", n.Type)
		}
	}
	if len(csr.DNSNames) > 0 || len(csr.IPAddresses) > 0 || len(csr.URIs) > 0 {
		return errors.New("csr must not contain DNS/IP/URI subject alternative names")
	}
	for _, e := range csr.EmailAddresses {
		if email == "" || !strings.EqualFold(e, email) {
			return errors.New("csr email SAN does not match the user's email")
		}
	}
	return nil
}

func render(w http.ResponseWriter, name string, data any) {
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("template %s: %v", name, err)
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	user := s.authenticatedUser(r)
	data := map[string]interface{}{
		"User":   user,
		"Domain": s.cfg.Domain,
	}
	render(w, "index.html", data)
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.cfg.listUsers()
	if err != nil {
		log.Printf("list users: %v", err)
		http.Error(w, "Failed to list users", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"User":   s.authenticatedUser(r),
		"Users":  users,
		"Domain": s.cfg.Domain,
	}
	render(w, "users.html", data)
}

func (s *Server) handleCerts(w http.ResponseWriter, r *http.Request) {
	certs, err := s.cfg.listCerts()
	if err != nil {
		log.Printf("list certs: %v", err)
		http.Error(w, "Failed to list certificates", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"User":   s.authenticatedUser(r),
		"Certs":  certs,
		"Domain": s.cfg.Domain,
		"Now":    time.Now(),
	}
	render(w, "certs.html", data)
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	user, err := s.cfg.getUser(username)
	if err != nil {
		log.Printf("get user %q: %v", username, err)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	data := map[string]interface{}{
		"User":       s.authenticatedUser(r),
		"EnrollUser": user,
		"Domain":     s.cfg.Domain,
		"TTL":        s.cfg.CertTTL,
	}
	render(w, "enroll.html", data)
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isAdmin(r) {
		log.Printf("sign: denied, caller %q lacks %s", r.Header.Get("X-Forwarded-User"), adminGroup)
		http.Error(w, "Forbidden: "+adminGroup+" membership required", http.StatusForbidden)
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		CSR      string `json:"csr"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.CSR == "" || req.Username == "" {
		http.Error(w, "username and csr are required", http.StatusBadRequest)
		return
	}

	// Verify user exists in LDAP
	user, err := s.cfg.getUser(req.Username)
	if err != nil {
		log.Printf("sign: get user %q: %v", req.Username, err)
		http.Error(w, "User not found in directory", http.StatusNotFound)
		return
	}

	// Validate against the directory record, not the client-supplied email.
	if err := validateCSR(req.CSR, user.Username, user.Email); err != nil {
		log.Printf("sign: rejected CSR for %q: %v", req.Username, err)
		http.Error(w, "Invalid CSR: "+err.Error(), http.StatusBadRequest)
		return
	}

	resp, err := s.cfg.signCSR(user.Username, user.Email, req.CSR)
	if err != nil {
		log.Printf("sign: vault error for %q: %v", req.Username, err)
		http.Error(w, "Failed to sign CSR", http.StatusInternalServerError)
		return
	}
	log.Printf("sign: issued serial %s for %q (by %q)", resp.Serial, user.Username, r.Header.Get("X-Forwarded-User"))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleAPIUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.cfg.listUsers()
	if err != nil {
		log.Printf("api users: %v", err)
		http.Error(w, "Failed to list users", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func main() {
	cfg := loadConfig()
	srv := &Server{cfg: cfg}

	var err error
	templates, err = template.ParseFS(webFS, "web/*.html")
	if err != nil {
		log.Fatalf("Failed to parse templates: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", srv.handleIndex)
	mux.HandleFunc("GET /users", srv.handleUsers)
	mux.HandleFunc("GET /certs", srv.handleCerts)
	mux.HandleFunc("GET /enroll/{username}", srv.handleEnroll)
	mux.HandleFunc("POST /api/sign", srv.handleSign)
	mux.HandleFunc("GET /api/users", srv.handleAPIUsers)

	// Surface Vault credential problems at start-up (non-fatal: the files
	// may be written by `portcullis vault init` after enroll starts; every request
	// retries the login).
	if _, err := cfg.vault.client(false); err != nil {
		log.Printf("WARNING: Vault AppRole login failed: %v", err)
	} else {
		log.Printf("Vault AppRole login OK (%s)", cfg.VaultAddr)
	}

	log.Printf("Portcullis Enrollment UI listening on %s", cfg.ListenAddr)
	log.Printf("Domain: %s", cfg.Domain)
	// Reject cross-origin browser POSTs (Sec-Fetch-Site / Origin vs Host).
	// Together with the application/json requirement on /api/sign this
	// closes CSRF against the admin's forward-auth session cookie.
	handler := http.NewCrossOriginProtection().Handler(mux)
	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(httpSrv.ListenAndServe())
}
