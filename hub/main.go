package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed web/*
var webFS embed.FS

// Auth describes how an app handles authentication.
type Auth struct {
	Method      string      `yaml:"method" json:"method"`
	SSO         interface{} `yaml:"sso" json:"sso"` // true, false, or "partial"
	GroupAccess bool        `yaml:"group_access" json:"group_access"`
	GroupAdmin  bool        `yaml:"group_admin" json:"group_admin"`
	AccessGroup string      `yaml:"access_group" json:"access_group"`
	AdminGroup  string      `yaml:"admin_group" json:"admin_group"`
	Notes       string      `yaml:"notes" json:"notes"`
}

// SettingTarget maps a setting to a compose service volume mount.
type SettingTarget struct {
	Service string `yaml:"service" json:"service"`
	Mount   string `yaml:"mount" json:"mount"`
}

// Setting is a user-configurable option defined in a manifest.
type Setting struct {
	Key         string         `yaml:"key" json:"key"`
	Label       string         `yaml:"label" json:"label"`
	Description string         `yaml:"description" json:"description"`
	Type        string         `yaml:"type" json:"type"` // text, path, paths, boolean, select
	Required    bool           `yaml:"required" json:"required"`
	Default     string         `yaml:"default" json:"default"`
	Options     []string       `yaml:"options" json:"options"`
	Target      *SettingTarget `yaml:"target" json:"target"`
}

// ContainerStatus holds Docker container state info.
type ContainerStatus struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Status string `json:"status"`
}

// Manifest describes an app template.
type Manifest struct {
	Name        string            `yaml:"name" json:"name"`
	Description string            `yaml:"description" json:"description"`
	Icon        string            `yaml:"icon" json:"icon"`
	Category    string            `yaml:"category" json:"category"`
	Tags        []string          `yaml:"tags" json:"tags"`
	Conflicts   []string          `yaml:"conflicts" json:"conflicts"`
	Auth        Auth              `yaml:"auth" json:"auth"`
	Settings    []Setting         `yaml:"settings" json:"settings"`
	Env         []EnvVar          `yaml:"env" json:"env"`
	Clients     []KeycloakClient  `yaml:"keycloak_clients" json:"keycloak_clients"`
	ConfigFiles []ConfigFile      `yaml:"config_files" json:"config_files"`
	URLs        []AppURL          `yaml:"urls" json:"urls"`
}

type EnvVar struct {
	Key         string `yaml:"key" json:"key"`
	Description string `yaml:"description" json:"description"`
	Generate    string `yaml:"generate" json:"generate"` // "random", "none", ""
	Required    *bool  `yaml:"required" json:"required"`
}

type KeycloakClient struct {
	ClientID     string   `yaml:"client_id" json:"client_id"`
	SecretEnv    string   `yaml:"secret_env" json:"secret_env"`
	RedirectURI  string   `yaml:"redirect_uri" json:"redirect_uri"`
	RedirectURIs []string `yaml:"redirect_uris" json:"redirect_uris"`
	Name         string   `yaml:"name" json:"name"`
}

type ConfigFile struct {
	Src  string `yaml:"src" json:"src"`
	Dest string `yaml:"dest" json:"dest"`
}

type AppURL struct {
	Label string `yaml:"label" json:"label"`
	URL   string `yaml:"url" json:"url"`
}

// Source is a template repository.
type Source struct {
	Name string `json:"name" yaml:"name"`
	URL  string `json:"url" yaml:"url"`
	Path string `json:"path" yaml:"path"` // local path after clone
}

// AppState tracks which apps are enabled and their settings.
type AppState struct {
	Enabled        []string                     `json:"enabled" yaml:"enabled"`
	Sources        []Source                     `json:"sources" yaml:"sources"`
	Settings       map[string]map[string]string `json:"settings" yaml:"settings"`
	MigrateVersion int                          `json:"migrate_version" yaml:"migrate_version"`
}

// Template is a discovered template with its source info.
type Template struct {
	ID       string   `json:"id"`
	Source   string   `json:"source"` // "local" or repo name
	Manifest Manifest `json:"manifest"`
	Path     string   `json:"-"` // filesystem path
	Enabled  bool     `json:"enabled"`
}

var (
	projectDir     string
	projectHostDir string // host path for --project-directory (Docker daemon resolves bind mounts here)
	dataDir        string
	templates      []Template
	state          AppState
	stateMu        sync.RWMutex
	domain         string
	lldapURL       string
	lldapUser       string
	lldapPass      string
)

// resolveUsername converts an email (from forward-auth) to an LLDAP username.
func resolveUsername(email string) string {
	if lldapPass == "" || !strings.Contains(email, "@") {
		return email
	}
	// Get LLDAP auth token
	loginBody := fmt.Sprintf(`{"username":"%s","password":"%s"}`, lldapUser, lldapPass)
	resp, err := http.Post(lldapURL+"/auth/simple/login", "application/json", strings.NewReader(loginBody))
	if err != nil || resp.StatusCode != 200 {
		return email
	}
	defer resp.Body.Close()
	var tokenResp struct{ Token string `json:"token"` }
	if json.NewDecoder(resp.Body).Decode(&tokenResp) != nil || tokenResp.Token == "" {
		return email
	}
	// Query for user by email
	query := fmt.Sprintf(`{"query":"{users(filters:{eq:{field:\"email\",value:\"%s\"}}){id}}"}`, email)
	req, _ := http.NewRequest("POST", lldapURL+"/api/graphql", strings.NewReader(query))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tokenResp.Token)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil || resp2.StatusCode != 200 {
		return email
	}
	defer resp2.Body.Close()
	var gqlResp struct {
		Data struct {
			Users []struct{ ID string `json:"id"` } `json:"users"`
		} `json:"data"`
	}
	if json.NewDecoder(resp2.Body).Decode(&gqlResp) != nil || len(gqlResp.Data.Users) == 0 {
		return email
	}
	return gqlResp.Data.Users[0].ID
}

func main() {
	projectDir = os.Getenv("PROJECT_DIR")
	if projectDir == "" {
		projectDir = "/app/project"
	}
	projectHostDir = os.Getenv("PROJECT_HOST_DIR")
	if projectHostDir == "" {
		projectHostDir = projectDir // fallback: same as container path (works if not in Docker)
	}
	dataDir = os.Getenv("HUB_DATA_DIR")
	if dataDir == "" {
		dataDir = filepath.Join(projectDir, ".hub")
	}
	domain = os.Getenv("PORTCULLIS_DOMAIN")
	if domain == "" {
		domain = "portcullis.local"
	}
	lldapURL = os.Getenv("LLDAP_HTTP_URL")
	if lldapURL == "" {
		lldapURL = "http://lldap:17170"
	}
	lldapUser = os.Getenv("LLDAP_ADMIN_USER")
	if lldapUser == "" {
		lldapUser = "admin"
	}
	lldapPass = os.Getenv("LLDAP_ADMIN_PASSWORD")

	os.MkdirAll(dataDir, 0755)
	os.MkdirAll(filepath.Join(dataDir, "repos"), 0755)

	loadState()
	autoLoadDefaultTemplates()
	discoverTemplates()
	migrateToIsolatedStacks()

	mux := http.NewServeMux()

	// Pages
	mux.HandleFunc("/", handleIndex)

	// API
	mux.HandleFunc("/api/templates", handleTemplates)
	mux.HandleFunc("/api/templates/enable", handleEnable)
	mux.HandleFunc("/api/templates/disable", handleDisable)
	mux.HandleFunc("/api/sources", handleSources)
	mux.HandleFunc("/api/sources/add", handleAddSource)
	mux.HandleFunc("/api/sources/remove", handleRemoveSource)
	mux.HandleFunc("/api/sources/sync", handleSyncSources)
	mux.HandleFunc("/api/status", handleStatus)
	mux.HandleFunc("/api/templates/settings/", handleTemplateSettings)
	mux.HandleFunc("/api/templates/status/", handleTemplateStatus)
	mux.HandleFunc("/api/templates/logs/", handleTemplateLogs)
	mux.HandleFunc("/api/templates/compose/", handleTemplateCompose)
	mux.HandleFunc("/api/templates/env/", handleTemplateEnv)
	mux.HandleFunc("/api/templates/exec/", handleTemplateExec)
	mux.HandleFunc("/api/templates/restart/", handleTemplateRestart)

	// Static assets
	mux.HandleFunc("/static/", handleStatic)

	addr := ":8888"
	log.Printf("Hub listening on %s (domain: %s)", addr, domain)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// ── State persistence ────────────────────────────────────

func statePath() string {
	return filepath.Join(dataDir, "state.yaml")
}

func loadState() {
	data, err := os.ReadFile(statePath())
	if err != nil {
		state = AppState{Settings: make(map[string]map[string]string)}
		return
	}
	yaml.Unmarshal(data, &state)
	if state.Settings == nil {
		state.Settings = make(map[string]map[string]string)
	}
}

func saveState() {
	data, _ := yaml.Marshal(&state)
	os.WriteFile(statePath(), data, 0644)
}

// ── Template discovery ───────────────────────────────────

func discoverTemplates() {
	stateMu.Lock()
	defer stateMu.Unlock()

	templates = nil

	// Local templates
	localDir := filepath.Join(projectDir, "templates")
	discoverFrom(localDir, "local")

	// Remote repo templates
	for _, src := range state.Sources {
		if src.Path != "" {
			discoverFrom(src.Path, src.Name)
		}
	}

	// Mark enabled
	enabledSet := make(map[string]bool)
	for _, id := range state.Enabled {
		enabledSet[id] = true
	}
	for i := range templates {
		templates[i].Enabled = enabledSet[templates[i].ID]
	}

	sort.Slice(templates, func(i, j int) bool {
		if templates[i].Manifest.Category != templates[j].Manifest.Category {
			return templates[i].Manifest.Category < templates[j].Manifest.Category
		}
		return templates[i].Manifest.Name < templates[j].Manifest.Name
	})
}

func discoverFrom(dir, source string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		manifestPath := filepath.Join(dir, e.Name(), "manifest.yaml")
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			continue
		}
		var m Manifest
		if err := yaml.Unmarshal(data, &m); err != nil {
			log.Printf("Bad manifest in %s: %v", manifestPath, err)
			continue
		}
		// Substitute {{DOMAIN}} in app URLs
		for i := range m.URLs {
			m.URLs[i].URL = strings.ReplaceAll(m.URLs[i].URL, "{{DOMAIN}}", domain)
		}
		templates = append(templates, Template{
			ID:       e.Name(),
			Source:   source,
			Manifest: m,
			Path:     filepath.Join(dir, e.Name()),
		})
	}
}

// ── Auto-load default templates ──────────────────────────

func autoLoadDefaultTemplates() {
	defaultURL := os.Getenv("DEFAULT_TEMPLATES_URL")
	if defaultURL == "" {
		return
	}

	stateMu.RLock()
	hasSources := len(state.Sources) > 0
	stateMu.RUnlock()

	if hasSources {
		return // already has sources, don't auto-add
	}

	log.Printf("First run: cloning default templates from %s", defaultURL)
	if err := addSource("portcullis", defaultURL); err != nil {
		log.Printf("Warning: could not clone default templates: %v", err)
	} else {
		log.Println("Default templates loaded successfully")
	}
}

// ── Migration ────────────────────────────────────────────

// migrateToIsolatedStacks migrates apps from the shared portcullis project
// to per-app isolated projects (portcullis-<app-id>).
func migrateToIsolatedStacks() {
	if state.MigrateVersion >= 2 {
		return // already migrated
	}

	stateMu.Lock()
	enabledApps := make([]string, len(state.Enabled))
	copy(enabledApps, state.Enabled)
	stateMu.Unlock()

	if len(enabledApps) == 0 {
		stateMu.Lock()
		state.MigrateVersion = 2
		saveState()
		stateMu.Unlock()
		return
	}

	log.Printf("Migrating %d apps to isolated stacks...", len(enabledApps))

	for _, id := range enabledApps {
		tmpl := findTemplate(id)
		if tmpl == nil {
			continue
		}

		// Generate per-app .env
		if err := generateAppEnv(tmpl); err != nil {
			log.Printf("Migration warning: could not generate env for %s: %v", id, err)
		}

		// Stop under old shared project name
		composePath := filepath.Join(tmpl.Path, "compose.yml")
		if _, err := os.Stat(composePath); err != nil {
			continue
		}
		envFile := appEnvPath(tmpl)
		oldArgs := []string{"compose", "-p", "portcullis", "-f", composePath,
			"--project-directory", projectHostDir, "--env-file", envFile, "down"}
		cmd := exec.Command("docker", oldArgs...)
		cmd.Env = append(os.Environ(), "COMPOSE_IGNORE_ORPHANS=true")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Printf("Migration: old stack down for %s: %v (may already be stopped)", id, err)
		}

		// Start under new isolated project name
		if err := composeUp(tmpl); err != nil {
			log.Printf("Migration warning: could not start %s under new project: %v", id, err)
		} else {
			log.Printf("Migrated %s → %s", id, appProjectName(tmpl))
		}
	}

	stateMu.Lock()
	state.MigrateVersion = 2
	saveState()
	stateMu.Unlock()
	log.Println("Migration complete")
}

// ── Enable / Disable ─────────────────────────────────────

func enableApp(id string) error {
	stateMu.Lock()
	defer stateMu.Unlock()

	var tmpl *Template
	for i := range templates {
		if templates[i].ID == id {
			tmpl = &templates[i]
			break
		}
	}
	if tmpl == nil {
		return fmt.Errorf("template not found: %s", id)
	}

	// Check conflicts
	for _, conflict := range tmpl.Manifest.Conflicts {
		for _, enabled := range state.Enabled {
			if enabled == conflict {
				return fmt.Errorf("%s conflicts with enabled app %s", id, conflict)
			}
		}
	}

	// Check if already enabled
	for _, enabled := range state.Enabled {
		if enabled == id {
			return nil
		}
	}

	// Generate per-app .env file
	if err := generateAppEnv(tmpl); err != nil {
		return fmt.Errorf("env setup failed: %w", err)
	}

	// Copy config files
	for _, cf := range tmpl.Manifest.ConfigFiles {
		src := filepath.Join(tmpl.Path, cf.Src)
		dest := filepath.Join(projectDir, cf.Dest)
		os.MkdirAll(filepath.Dir(dest), 0755)
		if err := copyFile(src, dest); err != nil {
			log.Printf("Warning: failed to copy %s → %s: %v", src, dest, err)
		}
	}

	// Register Keycloak clients
	for _, client := range tmpl.Manifest.Clients {
		if err := registerKeycloakClient(client, tmpl); err != nil {
			log.Printf("Warning: failed to register client %s: %v", client.ClientID, err)
		}
	}

	state.Enabled = append(state.Enabled, id)
	tmpl.Enabled = true
	saveState()

	// Bring up just this app's services
	if err := composeUp(tmpl); err != nil {
		return fmt.Errorf("compose up failed: %w", err)
	}

	return nil
}

func disableApp(id string) error {
	stateMu.Lock()
	defer stateMu.Unlock()

	found := false
	newEnabled := make([]string, 0, len(state.Enabled))
	for _, enabled := range state.Enabled {
		if enabled == id {
			found = true
			continue
		}
		newEnabled = append(newEnabled, enabled)
	}
	if !found {
		return fmt.Errorf("app not enabled: %s", id)
	}

	state.Enabled = newEnabled
	for i := range templates {
		if templates[i].ID == id {
			templates[i].Enabled = false
			break
		}
	}
	saveState()

	// Stop the app's services
	tmpl := findTemplate(id)
	if tmpl != nil {
		return composeDown(tmpl)
	}
	return nil
}

func findTemplate(id string) *Template {
	for i := range templates {
		if templates[i].ID == id {
			return &templates[i]
		}
	}
	return nil
}

// ── Compose management ───────────────────────────────────

func appProjectName(tmpl *Template) string {
	return "portcullis-" + tmpl.ID
}

func appEnvPath(tmpl *Template) string {
	// Store per-app .env in Hub data dir (writable), not in templates (read-only)
	envDir := filepath.Join(dataDir, "env")
	os.MkdirAll(envDir, 0755)
	return filepath.Join(envDir, tmpl.ID+".env")
}

func appOverridePath(tmpl *Template) string {
	overrideDir := filepath.Join(dataDir, "overrides")
	os.MkdirAll(overrideDir, 0755)
	return filepath.Join(overrideDir, tmpl.ID+".override.yml")
}

func composeBaseArgs(tmpl *Template) []string {
	composePath := filepath.Join(tmpl.Path, "compose.yml")
	envFile := appEnvPath(tmpl)
	args := []string{"compose", "-p", appProjectName(tmpl), "-f", composePath}
	// Include hub-generated override if present
	overridePath := appOverridePath(tmpl)
	if _, err := os.Stat(overridePath); err == nil {
		args = append(args, "-f", overridePath)
	}
	args = append(args, "--project-directory", projectHostDir, "--env-file", envFile)
	return args
}

func composeUp(tmpl *Template) error {
	composePath := filepath.Join(tmpl.Path, "compose.yml")
	if _, err := os.Stat(composePath); err != nil {
		return nil
	}
	args := append(composeBaseArgs(tmpl), "up", "-d", "--no-deps")
	cmd := exec.Command("docker", args...)
	cmd.Env = append(os.Environ(), "COMPOSE_IGNORE_ORPHANS=true")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func composeDown(tmpl *Template) error {
	composePath := filepath.Join(tmpl.Path, "compose.yml")
	if _, err := os.Stat(composePath); err != nil {
		return nil
	}
	args := append(composeBaseArgs(tmpl), "down")
	cmd := exec.Command("docker", args...)
	cmd.Env = append(os.Environ(), "COMPOSE_IGNORE_ORPHANS=true")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// generateComposeOverride writes a compose override file with user-configured volume mounts.
func generateComposeOverride(tmpl *Template, values map[string]string) error {
	overridePath := appOverridePath(tmpl)
	serviceMounts := make(map[string][]string)
	for _, s := range tmpl.Manifest.Settings {
		val := values[s.Key]
		if val == "" || s.Target == nil || s.Target.Mount == "" {
			continue
		}
		if s.Type == "path" {
			mount := fmt.Sprintf("%s:%s", val, s.Target.Mount)
			serviceMounts[s.Target.Service] = append(serviceMounts[s.Target.Service], mount)
		}
	}
	if len(serviceMounts) == 0 {
		os.Remove(overridePath)
		return nil
	}
	var buf strings.Builder
	buf.WriteString("# Auto-generated by Portcullis Hub -- do not edit\nservices:\n")
	for svc, mounts := range serviceMounts {
		buf.WriteString(fmt.Sprintf("  %s:\n    volumes:\n", svc))
		for _, m := range mounts {
			buf.WriteString(fmt.Sprintf("      - %s\n", m))
		}
	}
	return os.WriteFile(overridePath, []byte(buf.String()), 0644)
}

// ── Env var management ───────────────────────────────────

// generateAppEnv creates a per-app .env file with only the variables this app needs.
func generateAppEnv(tmpl *Template) error {
	envFile := appEnvPath(tmpl)
	vars := make(map[string]string)

	// Always include PORTCULLIS_DOMAIN
	vars["PORTCULLIS_DOMAIN"] = domain

	// Read existing per-app env (preserve user edits)
	existing, _ := os.ReadFile(envFile)
	for _, line := range strings.Split(string(existing), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
			vars[parts[0]] = parts[1]
		}
	}

	// Generate manifest env vars (secrets, API keys)
	for _, v := range tmpl.Manifest.Env {
		if _, exists := vars[v.Key]; exists {
			continue // don't overwrite existing
		}
		switch v.Generate {
		case "random":
			b := make([]byte, 24)
			rand.Read(b)
			vars[v.Key] = hex.EncodeToString(b)[:32]
		default:
			vars[v.Key] = ""
		}
	}

	// Include user settings
	stateMu.RLock()
	if settings, ok := state.Settings[tmpl.ID]; ok {
		for k, v := range settings {
			vars[k] = v
		}
	}
	stateMu.RUnlock()

	// Also pull any ${VAR} references from compose that might come from core .env
	coreEnv := readEnvFile(filepath.Join(projectDir, ".env"))
	composeData, _ := os.ReadFile(filepath.Join(tmpl.Path, "compose.yml"))
	for ref := range extractEnvRefs(string(composeData)) {
		if _, exists := vars[ref]; !exists {
			if coreVal, ok := coreEnv[ref]; ok {
				vars[ref] = coreVal
			}
		}
	}

	// Write the per-app .env
	var lines []string
	lines = append(lines, "# Auto-generated by Portcullis Hub — do not edit manually")
	lines = append(lines, fmt.Sprintf("# App: %s", tmpl.Manifest.Name))

	// Sort keys for deterministic output
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		lines = append(lines, fmt.Sprintf("%s=%s", k, vars[k]))
	}
	return os.WriteFile(envFile, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

// readEnvFile parses a .env file into a map.
func readEnvFile(path string) map[string]string {
	result := make(map[string]string)
	data, err := os.ReadFile(path)
	if err != nil {
		return result
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
			result[parts[0]] = parts[1]
		}
	}
	return result
}

// ensureEnvVars appends missing vars to root .env (legacy, used by core services).
func ensureEnvVars(vars []EnvVar) error {
	envFile := filepath.Join(projectDir, ".env")
	existing, _ := os.ReadFile(envFile)
	existingStr := string(existing)
	var additions []string
	for _, v := range vars {
		if strings.Contains(existingStr, v.Key+"=") {
			continue
		}
		var value string
		switch v.Generate {
		case "random":
			b := make([]byte, 24)
			rand.Read(b)
			value = hex.EncodeToString(b)[:32]
		default:
			value = ""
		}
		additions = append(additions, fmt.Sprintf("%s=%s", v.Key, value))
	}
	if len(additions) > 0 {
		f, err := os.OpenFile(envFile, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		defer f.Close()
		for _, line := range additions {
			f.WriteString(line + "\n")
		}
	}
	return nil
}

// ── Keycloak client registration ─────────────────────────

func registerKeycloakClient(client KeycloakClient, tmpl *Template) error {
	// Read secret from per-app .env first, then fall back to core .env
	secretVal := ""
	for _, envPath := range []string{appEnvPath(tmpl), filepath.Join(projectDir, ".env")} {
		data, err := os.ReadFile(envPath)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, client.SecretEnv+"=") {
				secretVal = strings.TrimPrefix(line, client.SecretEnv+"=")
				break
			}
		}
		if secretVal != "" {
			break
		}
	}

	// Build redirect URI list
	var redirectURIs []string
	if len(client.RedirectURIs) > 0 {
		for _, uri := range client.RedirectURIs {
			redirectURIs = append(redirectURIs, strings.ReplaceAll(uri, "{{DOMAIN}}", domain))
		}
	} else if client.RedirectURI != "" {
		redirectURIs = []string{strings.ReplaceAll(client.RedirectURI, "{{DOMAIN}}", domain)}
	}

	keycloakURL := os.Getenv("KEYCLOAK_URL")
	if keycloakURL == "" {
		keycloakURL = "http://keycloak:8080"
	}

	// Get admin token
	cmd := exec.Command("curl", "-sk",
		keycloakURL+"/realms/master/protocol/openid-connect/token",
		"-d", "client_id=admin-cli",
		"-d", "username="+os.Getenv("KEYCLOAK_ADMIN"),
		"-d", "password="+os.Getenv("KEYCLOAK_ADMIN_PASSWORD"),
		"-d", "grant_type=password")
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("keycloak auth failed: %w", err)
	}

	var tokenResp map[string]interface{}
	json.Unmarshal(out, &tokenResp)
	token, _ := tokenResp["access_token"].(string)
	if token == "" {
		return fmt.Errorf("no access token from keycloak")
	}

	// Register client
	payload, _ := json.Marshal(map[string]interface{}{
		"clientId":                client.ClientID,
		"name":                   client.Name,
		"enabled":                true,
		"protocol":               "openid-connect",
		"publicClient":           false,
		"secret":                 secretVal,
		"redirectUris":           redirectURIs,
		"standardFlowEnabled":    true,
		"directAccessGrantsEnabled": false,
	})

	cmd = exec.Command("curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
		keycloakURL+"/admin/realms/portcullis/clients",
		"-H", "Authorization: Bearer "+token,
		"-H", "Content-Type: application/json",
		"-d", string(payload))
	out, err = cmd.Output()
	if err != nil {
		return fmt.Errorf("client registration failed: %w", err)
	}

	code := strings.TrimSpace(string(out))
	if code != "201" && code != "409" {
		return fmt.Errorf("unexpected response: %s", code)
	}
	log.Printf("Registered Keycloak client %s (HTTP %s)", client.ClientID, code)
	return nil
}

// ── Source management ────────────────────────────────────

func addSource(name, url string) error {
	stateMu.Lock()
	defer stateMu.Unlock()

	for _, s := range state.Sources {
		if s.Name == name {
			return fmt.Errorf("source already exists: %s", name)
		}
	}

	repoDir := filepath.Join(dataDir, "repos", name)
	cmd := exec.Command("git", "clone", "--depth=1", url, repoDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git clone failed: %w", err)
	}

	state.Sources = append(state.Sources, Source{
		Name: name,
		URL:  url,
		Path: repoDir,
	})
	saveState()

	// Re-discover templates
	stateMu.Unlock()
	discoverTemplates()
	stateMu.Lock()

	return nil
}

func removeSource(name string) error {
	stateMu.Lock()
	defer stateMu.Unlock()

	found := false
	newSources := make([]Source, 0)
	for _, s := range state.Sources {
		if s.Name == name {
			found = true
			os.RemoveAll(s.Path)
			continue
		}
		newSources = append(newSources, s)
	}
	if !found {
		return fmt.Errorf("source not found: %s", name)
	}

	// Disable any apps from this source
	newEnabled := make([]string, 0)
	for _, id := range state.Enabled {
		tmpl := findTemplate(id)
		if tmpl != nil && tmpl.Source == name {
			continue
		}
		newEnabled = append(newEnabled, id)
	}
	state.Enabled = newEnabled
	state.Sources = newSources
	saveState()

	stateMu.Unlock()
	discoverTemplates()
	stateMu.Lock()

	return nil
}

func syncSources() error {
	stateMu.RLock()
	sources := make([]Source, len(state.Sources))
	copy(sources, state.Sources)
	stateMu.RUnlock()

	for _, s := range sources {
		if s.Path != "" {
			cmd := exec.Command("git", "-C", s.Path, "pull", "--ff-only")
			cmd.Run()
		}
	}

	discoverTemplates()
	return nil
}

// ── HTTP Handlers ────────────────────────────────────────

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	tmpl, err := template.ParseFS(webFS, "web/index.html")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	stateMu.RLock()
	defer stateMu.RUnlock()

	// Group by category
	categories := make(map[string][]Template)
	for _, t := range templates {
		categories[t.Manifest.Category] = append(categories[t.Manifest.Category], t)
	}

	user := r.Header.Get("X-Forwarded-User")
	if user != "" {
		user = resolveUsername(user)
	}

	portalName := os.Getenv("PORTAL_DISPLAY_NAME")
	if portalName == "" {
		portalName = "Portcullis"
	}

	data := map[string]interface{}{
		"Domain":     domain,
		"PortalName": portalName,
		"Templates":  templates,
		"Categories": categories,
		"Sources":    state.Sources,
		"User":       user,
	}
	tmpl.Execute(w, data)
}

func handleTemplates(w http.ResponseWriter, r *http.Request) {
	stateMu.RLock()
	defer stateMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(templates)
}

func handleEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if err := enableApp(req.ID); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "enabled", "id": req.ID})
}

func handleDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if err := disableApp(req.ID); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "disabled", "id": req.ID})
}

func handleSources(w http.ResponseWriter, r *http.Request) {
	stateMu.RLock()
	defer stateMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(state.Sources)
}

func handleAddSource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.Name == "" || req.URL == "" {
		http.Error(w, "name and url required", 400)
		return
	}

	if err := addSource(req.Name, req.URL); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "added", "name": req.Name})
}

func handleRemoveSource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if err := removeSource(req.Name); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "removed", "name": req.Name})
}

func handleSyncSources(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	if err := syncSources(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "synced"})
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	stateMu.RLock()
	defer stateMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"domain":    domain,
		"templates": len(templates),
		"enabled":   len(state.Enabled),
		"sources":   len(state.Sources),
	})
}

func handleTemplateSettings(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/templates/settings/")
	tmpl := findTemplate(id)
	if tmpl == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		stateMu.RLock()
		values := state.Settings[id]
		stateMu.RUnlock()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"definitions": tmpl.Manifest.Settings,
			"values":      values,
		})
	case http.MethodPut:
		var values map[string]string
		json.NewDecoder(r.Body).Decode(&values)
		stateMu.Lock()
		state.Settings[id] = values
		saveState()
		stateMu.Unlock()
		// Write text/boolean/select settings to per-app .env
		for _, s := range tmpl.Manifest.Settings {
			if (s.Type == "text" || s.Type == "boolean" || s.Type == "select") && values[s.Key] != "" {
				setEnvVar(appEnvPath(tmpl), s.Key, values[s.Key])
			}
		}
		generateComposeOverride(tmpl, values)
		if tmpl.Enabled {
			go func() {
				composeDown(tmpl)
				composeUp(tmpl)
			}()
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
	default:
		http.Error(w, "GET or PUT only", 405)
	}
}

// composeServices reads the compose.yml and returns the list of service names.
func composeServices(tmpl *Template) []string {
	composePath := filepath.Join(tmpl.Path, "compose.yml")
	data, err := os.ReadFile(composePath)
	if err != nil {
		return nil
	}
	var compose struct {
		Services map[string]interface{} `yaml:"services"`
	}
	if yaml.Unmarshal(data, &compose) != nil {
		return nil
	}
	names := make([]string, 0, len(compose.Services))
	for name := range compose.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func handleTemplateStatus(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/templates/status/")
	tmpl := findTemplate(id)
	if tmpl == nil {
		http.NotFound(w, r)
		return
	}
	// Get service names from compose file, pass them to ps to filter
	services := composeServices(tmpl)
	args := append(composeBaseArgs(tmpl), "ps", "--format", "json")
	args = append(args, services...)
	cmd := exec.Command("docker", args...)
	cmd.Env = append(os.Environ(), "COMPOSE_IGNORE_ORPHANS=true")
	out, err := cmd.Output()
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		json.NewEncoder(w).Encode([]ContainerStatus{})
		return
	}
	var statuses []ContainerStatus
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		var raw map[string]interface{}
		if json.Unmarshal([]byte(line), &raw) != nil {
			continue
		}
		statuses = append(statuses, ContainerStatus{
			Name:   fmt.Sprint(raw["Name"]),
			State:  fmt.Sprint(raw["State"]),
			Status: fmt.Sprint(raw["Status"]),
		})
	}
	json.NewEncoder(w).Encode(statuses)
}

func handleTemplateLogs(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/templates/logs/")
	tmpl := findTemplate(id)
	if tmpl == nil {
		http.NotFound(w, r)
		return
	}
	lines := r.URL.Query().Get("lines")
	if lines == "" {
		lines = "200"
	}
	service := r.URL.Query().Get("service")
	args := append(composeBaseArgs(tmpl), "logs", "--tail", lines, "--no-color")
	if service != "" {
		args = append(args, service)
	} else {
		// Only show logs for services defined in this app's compose file
		args = append(args, composeServices(tmpl)...)
	}
	cmd := exec.Command("docker", args...)
	cmd.Env = append(os.Environ(), "COMPOSE_IGNORE_ORPHANS=true")
	out, _ := cmd.CombinedOutput()
	w.Header().Set("Content-Type", "text/plain")
	w.Write(out)
}

// ── Expert mode handlers ─────────────────────────────────

func handleTemplateCompose(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/templates/compose/")
	tmpl := findTemplate(id)
	if tmpl == nil {
		http.NotFound(w, r)
		return
	}
	composePath := filepath.Join(tmpl.Path, "compose.yml")

	switch r.Method {
	case http.MethodGet:
		data, err := os.ReadFile(composePath)
		if err != nil {
			http.Error(w, "compose.yml not found", 404)
			return
		}
		// Also read override if present
		overridePath := appOverridePath(tmpl)
		override, _ := os.ReadFile(overridePath)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"compose":  string(data),
			"override": string(override),
		})
	case http.MethodPut:
		var req struct {
			Compose  string `json:"compose"`
			Override string `json:"override"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		// Validate YAML
		var check interface{}
		if err := yaml.Unmarshal([]byte(req.Compose), &check); err != nil {
			http.Error(w, "Invalid YAML: "+err.Error(), 400)
			return
		}
		if err := os.WriteFile(composePath, []byte(req.Compose), 0644); err != nil {
			http.Error(w, "Failed to write: "+err.Error(), 500)
			return
		}
		overridePath := appOverridePath(tmpl)
		if req.Override != "" {
			os.WriteFile(overridePath, []byte(req.Override), 0644)
		} else {
			os.Remove(overridePath)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
	default:
		http.Error(w, "GET or PUT only", 405)
	}
}

func handleTemplateEnv(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/templates/env/")
	tmpl := findTemplate(id)
	if tmpl == nil {
		http.NotFound(w, r)
		return
	}

	// Read the per-app .env file
	appEnv := appEnvPath(tmpl)
	envData, _ := os.ReadFile(appEnv)
	services := composeServices(tmpl)

	switch r.Method {
	case http.MethodGet:
		// Build key-value map from per-app .env
		result := make(map[string]string)
		for _, line := range strings.Split(string(envData), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			result[parts[0]] = parts[1]
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"variables": result,
			"services":  services,
		})
	case http.MethodPut:
		var req map[string]string
		json.NewDecoder(r.Body).Decode(&req)
		for key, val := range req {
			setEnvVar(appEnv, key, val)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
	default:
		http.Error(w, "GET or PUT only", 405)
	}
}

// extractEnvRefs finds all ${VAR} and ${VAR:-default} references in a string.
func extractEnvRefs(s string) map[string]bool {
	refs := make(map[string]bool)
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '$' && s[i+1] == '{' {
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				continue
			}
			varExpr := s[i+2 : i+end]
			// Strip :-default suffix
			if idx := strings.Index(varExpr, ":-"); idx >= 0 {
				varExpr = varExpr[:idx]
			}
			refs[varExpr] = true
		}
	}
	return refs
}

func handleTemplateExec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/templates/exec/")
	tmpl := findTemplate(id)
	if tmpl == nil {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Service string `json:"service"`
		Command string `json:"command"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.Service == "" || req.Command == "" {
		http.Error(w, "service and command required", 400)
		return
	}
	// Validate service name is in the compose file
	valid := false
	for _, svc := range composeServices(tmpl) {
		if svc == req.Service {
			valid = true
			break
		}
	}
	if !valid {
		http.Error(w, "invalid service: "+req.Service, 400)
		return
	}
	// Execute: docker compose exec <service> <shell> -c <command>
	args := append(composeBaseArgs(tmpl), "exec", "-T", req.Service, "/bin/sh", "-c", req.Command)
	cmd := exec.Command("docker", args...)
	cmd.Env = append(os.Environ(), "COMPOSE_IGNORE_ORPHANS=true")
	out, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"output":   string(out),
		"exitCode": exitCode,
	})
}

func handleTemplateRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/templates/restart/")
	tmpl := findTemplate(id)
	if tmpl == nil {
		http.NotFound(w, r)
		return
	}
	if !tmpl.Enabled {
		http.Error(w, "app not enabled", 400)
		return
	}
	go func() {
		composeDown(tmpl)
		composeUp(tmpl)
	}()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "restarting"})
}

func handleStatic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/static/")
	data, err := webFS.ReadFile("web/" + path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if strings.HasSuffix(path, ".css") {
		w.Header().Set("Content-Type", "text/css")
	} else if strings.HasSuffix(path, ".js") {
		w.Header().Set("Content-Type", "application/javascript")
	}
	w.Write(data)
}

// setEnvVar updates or appends a key=value in the given .env file.
func setEnvVar(envFile, key, value string) {
	data, _ := os.ReadFile(envFile)
	lines := strings.Split(string(data), "\n")
	found := false
	for i, line := range lines {
		if strings.HasPrefix(line, key+"=") {
			lines[i] = key + "=" + value
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, key+"="+value)
	}
	os.WriteFile(envFile, []byte(strings.Join(lines, "\n")), 0644)
}

// ── Helpers ──────────────────────────────────────────────

func copyFile(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
