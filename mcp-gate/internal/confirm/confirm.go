// Package confirm decides companion tool calls that need a confirmation
// (integration contract §15.6) through the Hub's internal API (§15.7):
// consume an approved confirmation bound to (person, resource, tool,
// args_sha256), else create one and answer with its link. It fails
// closed (G26): any Hub error is returned and the bridge answers "can't
// check this right now; try again" without calling the upstream.
//
// Task 3b answers in the text form only ("This needs your confirmation in
// your browser: open <url>, then ask me to try again."), which §15.6
// gives every client; task 4 adds the URL-elicitation forms for clients
// that declared elicitation.url.
package confirm

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/portcullis/mcp-gate/internal/bridge"
	"github.com/portcullis/mcp-gate/internal/config"
	"github.com/portcullis/mcp-gate/internal/hubapi"
	mcp "github.com/portcullis/mcp-gate/internal/mcpsdk"
)

// Hub is the part of hubapi.Client the gate uses.
type Hub interface {
	CreateConfirmation(ctx context.Context, r hubapi.ConfirmRequest) (*hubapi.Confirmation, error)
	ConsumeConfirmation(ctx context.Context, r hubapi.ConsumeRequest) (id, state string, err error)
}

// Limits is the gate's confirmations_per_hour.
type Limits interface {
	AllowConfirm(user string) bool
}

// Gate implements bridge.Confirmer.
type Gate struct {
	Hub      Hub
	Limits   Limits
	Snapshot func() *config.Snapshot
}

// Texts of §15.6.
const (
	textPending  = "Still waiting for your confirmation in your browser"
	textDeclined = "You declined this in your browser"
	textTooMany  = "Too many confirmations requested; try again later"
)

func isError(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: msg}}}
}

// Before: consume a matching approved confirmation (proceed), else report
// a pending or declined one, else create one within the limits.
func (g *Gate) Before(ctx context.Context, c bridge.Call) (bridge.Outcome, error) {
	if c.Resource == nil || g.Hub == nil {
		return bridge.Outcome{}, errors.New("confirm: not configured")
	}
	sn := g.Snapshot()
	if sn == nil || sn.File == nil || sn.File.MainDomain == "" {
		return bridge.Outcome{}, errors.New("confirm: no configuration")
	}
	digest, err := ArgsDigest(c.Args)
	if err != nil {
		return bridge.Outcome{}, err
	}
	_, state, err := g.Hub.ConsumeConfirmation(ctx, hubapi.ConsumeRequest{User: c.User, Resource: c.Resource.URL, Tool: c.Tool, ArgsSHA256: digest})
	if err != nil {
		return bridge.Outcome{}, err
	}
	switch state {
	case hubapi.StateConsumed:
		return bridge.Outcome{Proceed: true}, nil
	case hubapi.StatePending:
		return bridge.Outcome{Answer: isError(textPending), Decision: "deny:pending"}, nil
	case hubapi.StateDeclined:
		return bridge.Outcome{Answer: isError(textDeclined), Decision: "deny:declined"}, nil
	case hubapi.StateNone:
	default:
		return bridge.Outcome{}, fmt.Errorf("confirm: unknown state")
	}
	if g.Limits != nil && !g.Limits.AllowConfirm(c.User) {
		return bridge.Outcome{Answer: isError(textTooMany), Decision: "rate_limited"}, nil
	}
	preview, err := Preview(c.Args)
	if err != nil {
		return bridge.Outcome{}, err
	}
	conf, err := g.Hub.CreateConfirmation(ctx, hubapi.ConfirmRequest{
		User: c.User, Client: c.Client, Resource: c.Resource.URL, Tool: c.Tool,
		ArgsSHA256: digest, ArgsPreview: preview, Reason: c.Reason,
	})
	switch {
	case errors.Is(err, hubapi.ErrTooMany):
		return bridge.Outcome{Answer: isError(textTooMany), Decision: "rate_limited"}, nil
	case errors.Is(err, hubapi.ErrNotAllowed):
		return bridge.Outcome{Answer: isError("you don't have access to " + c.Resource.Label), Decision: "deny:population"}, nil
	case err != nil:
		return bridge.Outcome{}, err
	}
	// The link must be the people listener's page for exactly this id
	// (§15.6): never a link the Hub answer could point elsewhere.
	want := "https://people." + sn.File.MainDomain + "/confirm/" + url.PathEscape(conf.ID)
	if conf.URL != want {
		return bridge.Outcome{}, errors.New("confirm: the Hub's link is not the people confirmation page")
	}
	return bridge.Outcome{
		Answer:   isError("This needs your confirmation in your browser: open " + conf.URL + ", then ask me to try again."),
		Decision: "confirm:" + conf.ID,
	}, nil
}
