package main

// Minimal Keycloak admin client for invites: the confidential client
// `portcullis-enroll` (service account, realm-management manage-users +
// view-users; created by `portcullis keycloak configure`) adds the required
// action webauthn-register-passwordless to the invited user, so the invite
// login cannot finish without registering a passkey.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const passkeyAction = "webauthn-register-passwordless"

type keycloakClient struct {
	base, realm, clientID string
	secretFile            string
	http                  *http.Client

	mu    sync.Mutex
	token string
	exp   time.Time
}

func newKeycloakClient(base, realm, clientID, secretFile string) *keycloakClient {
	return &keycloakClient{base: strings.TrimRight(base, "/"), realm: realm, clientID: clientID,
		secretFile: secretFile, http: &http.Client{Timeout: 15 * time.Second}}
}

func (k *keycloakClient) accessToken() (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.token != "" && time.Now().Before(k.exp) {
		return k.token, nil
	}
	secret, err := readInviteSecret(k.secretFile)
	if err != nil {
		return "", fmt.Errorf("client secret %s: %w", k.secretFile, err)
	}
	resp, err := k.http.PostForm(k.base+"/realms/"+k.realm+"/protocol/openid-connect/token", url.Values{
		"grant_type": {"client_credentials"}, "client_id": {k.clientID}, "client_secret": {secret},
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&tr) != nil || tr.AccessToken == "" {
		return "", fmt.Errorf("token endpoint: HTTP %d", resp.StatusCode)
	}
	k.token, k.exp = tr.AccessToken, time.Now().Add(time.Duration(tr.ExpiresIn-15)*time.Second)
	return k.token, nil
}

func (k *keycloakClient) do(method, path string, body any, out any) error {
	tok, err := k.accessToken()
	if err != nil {
		return err
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, k.base+"/admin/realms/"+k.realm+path, rd)
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := k.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: HTTP %d", method, path, resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// RequirePasskey imports the user from LDAP if needed (the exact-username
// search does that) and adds the passkey registration required action.
func (k *keycloakClient) RequirePasskey(username string) error {
	var users []struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	if err := k.do("GET", "/users?exact=true&username="+url.QueryEscape(username), nil, &users); err != nil {
		return err
	}
	if len(users) != 1 || users[0].Username != username {
		return fmt.Errorf("user %q not found in Keycloak", username)
	}
	var u struct {
		RequiredActions []string `json:"requiredActions"`
	}
	if err := k.do("GET", "/users/"+users[0].ID, nil, &u); err != nil {
		return err
	}
	for _, a := range u.RequiredActions {
		if a == passkeyAction {
			return nil
		}
	}
	return k.do("PUT", "/users/"+users[0].ID, map[string]any{"requiredActions": append(u.RequiredActions, passkeyAction)}, nil)
}
