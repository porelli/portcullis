package main

// Keycloak admin client for invites (gocloak): the confidential client
// `portcullis-enroll` (service account, realm-management manage-users +
// view-users; created by `portcullis keycloak configure`) adds the required
// action webauthn-register-passwordless to the invited user, so the invite
// login cannot finish without registering a passkey.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Nerzal/gocloak/v14"
)

const passkeyAction = "webauthn-register-passwordless"

type keycloakClient struct {
	realm, clientID string
	secretFile      string
	gc              *gocloak.GoCloak

	mu    sync.Mutex
	token string
	exp   time.Time
}

// quietLogger keeps resty (gocloak's HTTP layer) from logging on its own;
// errors are returned and logged by the caller.
type quietLogger struct{}

func (quietLogger) Errorf(string, ...any) {}
func (quietLogger) Warnf(string, ...any)  {}
func (quietLogger) Debugf(string, ...any) {}

func newKeycloakClient(base, realm, clientID, secretFile string) *keycloakClient {
	gc := gocloak.NewClient(strings.TrimRight(base, "/"))
	gc.RestyClient().SetTimeout(15 * time.Second).SetLogger(quietLogger{})
	return &keycloakClient{realm: realm, clientID: clientID, secretFile: secretFile, gc: gc}
}

// accessToken: client-credentials token of the service account, cached
// until 15 s before it expires. The secret file is re-read for every new
// token (it may be rotated) and only ever sent in the token request body.
func (k *keycloakClient) accessToken(ctx context.Context) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.token != "" && time.Now().Before(k.exp) {
		return k.token, nil
	}
	secret, err := readInviteSecret(k.secretFile)
	if err != nil {
		return "", fmt.Errorf("client secret %s: %w", k.secretFile, err)
	}
	tok, err := k.gc.LoginClient(ctx, k.clientID, secret, k.realm)
	if err != nil {
		return "", fmt.Errorf("token endpoint: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("token endpoint: no access_token")
	}
	k.token, k.exp = tok.AccessToken, time.Now().Add(time.Duration(tok.ExpiresIn-15)*time.Second)
	return k.token, nil
}

// RequirePasskey imports the user from LDAP if needed (the exact-username
// search does that) and adds the passkey registration required action.
func (k *keycloakClient) RequirePasskey(username string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tok, err := k.accessToken(ctx)
	if err != nil {
		return err
	}
	users, err := k.gc.GetUsers(ctx, tok, k.realm, gocloak.GetUsersParams{
		Username: gocloak.StringP(username), Exact: gocloak.BoolP(true)})
	if err != nil {
		return fmt.Errorf("user search: %w", err)
	}
	if len(users) != 1 || gocloak.PString(users[0].Username) != username || users[0].ID == nil {
		return fmt.Errorf("user %q not found in Keycloak", username)
	}
	id := *users[0].ID
	u, err := k.gc.GetUserByID(ctx, tok, k.realm, id)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	for _, a := range u.RequiredActions {
		if a == passkeyAction {
			return nil
		}
	}
	// Only id + requiredActions: Keycloak leaves absent fields unchanged.
	if err := k.gc.UpdateUser(ctx, tok, k.realm, gocloak.User{
		ID: gocloak.StringP(id), RequiredActions: append(u.RequiredActions, passkeyAction)}); err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	return nil
}
