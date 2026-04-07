package main

import (
	"crypto/x509"
	"embed"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	vault "github.com/hashicorp/vault/api"
)

//go:embed web/*
var webFS embed.FS

var templates *template.Template

type Config struct {
	VaultAddr      string
	VaultToken     string
	LDAPUrl        string
	LDAPBaseDN     string
	LDAPBindDN     string
	LDAPBindPass   string
	Domain         string
	ListenAddr     string
	CertTTL        string
	PKIRole        string
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
	return Config{
		VaultAddr:    envOr("VAULT_ADDR", "http://vault:8200"),
		VaultToken:   envOr("VAULT_TOKEN", "myroot"),
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

// Vault PKI operations

func (cfg *Config) vaultClient() (*vault.Client, error) {
	c, err := vault.NewClient(&vault.Config{Address: cfg.VaultAddr})
	if err != nil {
		return nil, err
	}
	c.SetToken(cfg.VaultToken)
	return c, nil
}

func (cfg *Config) signCSR(username, email, csr string) (*SignResponse, error) {
	vc, err := cfg.vaultClient()
	if err != nil {
		return nil, err
	}

	secret, err := vc.Logical().Write("pki_int/sign/"+cfg.PKIRole, map[string]interface{}{
		"csr":         csr,
		"common_name": username,
		"ttl":         cfg.CertTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("vault sign: %w", err)
	}

	cert := secret.Data["certificate"].(string)
	serial := secret.Data["serial_number"].(string)

	var caChain string
	if chain, ok := secret.Data["ca_chain"].([]interface{}); ok {
		parts := make([]string, len(chain))
		for i, c := range chain {
			parts[i] = c.(string)
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
	vc, err := cfg.vaultClient()
	if err != nil {
		return nil, err
	}

	secret, err := vc.Logical().List("pki_int/certs")
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data["keys"] == nil {
		return []CertInfo{}, nil
	}

	keys := secret.Data["keys"].([]interface{})
	certs := make([]CertInfo, 0, len(keys))

	for _, k := range keys {
		serial := k.(string)
		certSecret, err := vc.Logical().Read("pki_int/cert/" + serial)
		if err != nil || certSecret == nil {
			continue
		}

		certPEM := certSecret.Data["certificate"].(string)
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

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	user := s.authenticatedUser(r)
	data := map[string]interface{}{
		"User":   user,
		"Domain": s.cfg.Domain,
	}
	templates.ExecuteTemplate(w, "index.html", data)
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.cfg.listUsers()
	if err != nil {
		http.Error(w, "Failed to list users: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"User":   s.authenticatedUser(r),
		"Users":  users,
		"Domain": s.cfg.Domain,
	}
	templates.ExecuteTemplate(w, "users.html", data)
}

func (s *Server) handleCerts(w http.ResponseWriter, r *http.Request) {
	certs, err := s.cfg.listCerts()
	if err != nil {
		http.Error(w, "Failed to list certs: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"User":   s.authenticatedUser(r),
		"Certs":  certs,
		"Domain": s.cfg.Domain,
		"Now":    time.Now(),
	}
	templates.ExecuteTemplate(w, "certs.html", data)
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	user, err := s.cfg.getUser(username)
	if err != nil {
		http.Error(w, "User not found: "+err.Error(), http.StatusNotFound)
		return
	}

	data := map[string]interface{}{
		"User":       s.authenticatedUser(r),
		"EnrollUser": user,
		"Domain":     s.cfg.Domain,
		"TTL":        s.cfg.CertTTL,
	}
	templates.ExecuteTemplate(w, "enroll.html", data)
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		CSR      string `json:"csr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.CSR == "" || req.Username == "" {
		http.Error(w, "username and csr are required", http.StatusBadRequest)
		return
	}

	// Verify user exists in LDAP
	_, err := s.cfg.getUser(req.Username)
	if err != nil {
		http.Error(w, "User not found in directory", http.StatusNotFound)
		return
	}

	resp, err := s.cfg.signCSR(req.Username, req.Email, req.CSR)
	if err != nil {
		http.Error(w, "Failed to sign CSR: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleAPIUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.cfg.listUsers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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

	log.Printf("Portcullis Enrollment UI listening on %s", cfg.ListenAddr)
	log.Printf("Domain: %s", cfg.Domain)
	log.Fatal(http.ListenAndServe(cfg.ListenAddr, mux))
}
