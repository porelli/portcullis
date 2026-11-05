package bridge

import (
	"encoding/json"
	"strings"
	"testing"

	mcp "github.com/portcullis/mcp-gate/internal/mcpsdk"

	"github.com/portcullis/mcp-gate/internal/config"
)

func policyRes(mode string, writes, confirm, never []string) *config.Resource {
	return &config.Resource{
		URL: "https://gitea.example.com/mcp", Kind: config.KindCompanion, Label: "Gitea", Mode: mode,
		Tools: config.Tools{Writes: writes, Confirm: confirm, Never: never},
	}
}

func TestMatch(t *testing.T) {
	cases := []struct {
		pattern, tool, method string
		want                  bool
	}{
		{"create_*", "create_issue", "", true},
		{"create_*", "CREATE_Issue", "", true}, // case-folded both sides (G23)
		{"CREATE_*", "create_issue", "", true},
		{"*_write", "repo_write", "", true},
		{"*_write", "repo_writer", "", false},
		{"*", "anything", "", true},
		{"delete_*", "undelete_x", "", false},
		{"a*b*c", "aXXbYYc", "", true},
		{"a*b*c", "aXXcYYb", "", false},
		{"repo_write:delete", "repo_write", "delete", true},
		{"repo_write:delete", "repo_write", "DELETE", true},
		{"repo_write:delete", "repo_write", "read", false},
		{"repo_write:delete", "repo_write", "", false},
		{"repo_write:delete", "repo_read", "delete", false},
		{"list_issues", "list_issues", "", true},
		{"list_issues", "list_issue", "", false},
		{"merge_*", "MERGE_pr", "", true},
		{"delete_*", "delete_K", "", true}, // Kelvin sign folds to k
	}
	for _, c := range cases {
		if got := Match(c.pattern, c.tool, c.method); got != c.want {
			t.Errorf("Match(%q, %q, %q) = %v, want %v", c.pattern, c.tool, c.method, got, c.want)
		}
	}
}

func names(tools []*mcp.Tool) string {
	var out []string
	for _, t := range tools {
		out = append(out, t.Name)
	}
	return strings.Join(out, ",")
}

func TestToolFilter(t *testing.T) {
	writes := []string{"*_write", "create_*"}
	tools := []*mcp.Tool{
		{Name: "list_issues"}, {Name: "create_issue"}, {Name: "repo_write"},
		{Name: "Create_Label"}, {Name: "drop_db"}, {Name: "bad:name"}, {Name: ""}, nil,
		{Name: "get_file", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		{Name: "update_write", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, // readOnlyHint never unhides
	}
	never := []string{"drop_*", "repo_write:delete"}
	ro := policyRes("read_only", writes, nil, never)
	rw := policyRes("read_write", writes, nil, never)
	if got := names(FilterTools(ro, tools)); got != "list_issues,get_file" {
		t.Errorf("read_only: %s", got)
	}
	// never hidden in every mode; a method pattern never hides the tool.
	if got := names(FilterTools(rw, tools)); got != "list_issues,create_issue,repo_write,Create_Label,get_file,update_write" {
		t.Errorf("read_write: %s", got)
	}

	call := func(res *config.Resource, tool, args string, ann *mcp.ToolAnnotations) (bool, bool, string) {
		var raw json.RawMessage
		if args != "" {
			raw = json.RawMessage(args)
		}
		return CallDecision(res, tool, raw, ann)
	}
	for _, c := range []struct {
		res           *config.Resource
		tool, args    string
		allow, confrm bool
		reason        string
	}{
		{ro, "list_issues", `{}`, true, false, "allow"},
		{ro, "list_issues", ``, true, false, "allow"},
		{ro, "list_issues", `null`, true, false, "allow"},
		{ro, "create_issue", `{}`, false, false, "read_only"},
		{ro, "CREATE_ISSUE", `{}`, false, false, "read_only"},
		{rw, "create_issue", `{}`, true, false, "allow"},
		{rw, "drop_db", `{}`, false, false, "never"},
		{ro, "drop_db", `{}`, false, false, "never"},
		// tool:method — the call's arguments decide.
		{rw, "repo_write", `{"method":"delete"}`, false, false, "never"},
		{rw, "repo_write", `{"method":"DeLeTe"}`, false, false, "never"},
		{rw, "repo_write", `{"method":"read"}`, true, false, "allow"},
		{rw, "repo_write", `{}`, true, false, "allow"},
		// Fail closed: a case variant of the key, or a non-string method, counts.
		{rw, "repo_write", `{"Method":"delete"}`, false, false, "never"},
		{rw, "repo_write", `{"METHOD":"delete"}`, false, false, "never"},
		{rw, "repo_write", `{"method":["delete"]}`, false, false, "never"},
		{rw, "repo_write", `{"method":null}`, false, false, "never"},
		// Arguments that can be read two ways are refused.
		{rw, "repo_write", `{"method":"read","method":"delete"}`, false, false, "bad_arguments"},
		{rw, "repo_write", `{"method":"read","Method":"delete"}`, false, false, "bad_arguments"},
		{rw, "list_issues", `{"a":{"b":1,"b":2}}`, false, false, "bad_arguments"},
		{rw, "list_issues", `[1]`, false, false, "bad_arguments"},
		{rw, "list_issues", `"x"`, false, false, "bad_arguments"},
		{rw, "list_issues", `{"a":1} {}`, false, false, "bad_arguments"},
		{rw, "list_issues", "{\"a\":\"\xff\"}", false, false, "bad_arguments"},
		// Unlisted names are decided the same way; invalid names refused.
		{rw, "bad:name", `{}`, false, false, "bad_tool"},
		{rw, "", `{}`, false, false, "bad_tool"},
		{rw, strings.Repeat("a", 129), `{}`, false, false, "bad_tool"},
	} {
		allow, confirm, reason := call(c.res, c.tool, c.args, nil)
		if allow != c.allow || confirm != c.confrm || reason != c.reason {
			t.Errorf("%s %s %s: got (%v, %v, %q), want (%v, %v, %q)", c.res.Mode, c.tool, c.args, allow, confirm, reason, c.allow, c.confrm, c.reason)
		}
	}
}

func TestAnnotationAddsConfirmNeverRemoves(t *testing.T) {
	yes, no := true, false
	res := policyRes("read_write", []string{"*_write"}, []string{"delete_*", "repo_write:delete"}, nil)
	ro := policyRes("read_only", []string{"*_write"}, []string{"delete_*"}, nil)
	for _, c := range []struct {
		res           *config.Resource
		tool, args    string
		ann           *mcp.ToolAnnotations
		allow, confrm bool
		reason        string
	}{
		{res, "delete_repo", `{}`, nil, true, true, "confirm"},
		{res, "DELETE_repo", `{}`, &mcp.ToolAnnotations{DestructiveHint: &no, ReadOnlyHint: true}, true, true, "confirm"},
		{res, "repo_write", `{"method":"delete"}`, nil, true, true, "confirm"},
		{res, "repo_write", `{"Method":7}`, nil, true, true, "confirm"},
		{res, "repo_write", `{"method":"read"}`, nil, true, false, "allow"},
		{res, "wipe", `{}`, &mcp.ToolAnnotations{DestructiveHint: &yes}, true, true, "destructive"},
		{res, "wipe", `{}`, &mcp.ToolAnnotations{DestructiveHint: &yes, ReadOnlyHint: true}, true, true, "destructive"},
		{res, "wipe", `{}`, &mcp.ToolAnnotations{}, true, false, "allow"}, // missing hint changes nothing
		{res, "wipe", `{}`, nil, true, false, "allow"},
		{ro, "repo_write", `{}`, &mcp.ToolAnnotations{ReadOnlyHint: true}, false, false, "read_only"},
	} {
		var raw json.RawMessage
		if c.args != "" {
			raw = json.RawMessage(c.args)
		}
		allow, confirm, reason := CallDecision(c.res, c.tool, raw, c.ann)
		if allow != c.allow || confirm != c.confrm || reason != c.reason {
			t.Errorf("%s %s: got (%v, %v, %q), want (%v, %v, %q)", c.tool, c.args, allow, confirm, reason, c.allow, c.confrm, c.reason)
		}
	}
	// readOnlyHint on a writes tool keeps it hidden in read_only.
	if got := names(FilterTools(ro, []*mcp.Tool{{Name: "repo_write", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}})); got != "" {
		t.Errorf("readOnlyHint unhid a writes tool: %q", got)
	}
}

func TestURLElicitationHosts(t *testing.T) {
	res := &config.Resource{Kind: config.KindCompanion, Hosts: []string{"gitea.example.com", "git.example.org"}}
	for u, want := range map[string]bool{
		"https://gitea.example.com/x":         true,
		"https://GITEA.example.com/x?y=1":     true,
		"https://git.example.org/":            true,
		"https://gitea.example.com:443/x":     true,
		"https://people.example.com/confirm":  true,
		"https://auth.example.com/realms/x":   false,
		"https://hub.example.com/":            false,
		"https://mcp.example.com/mcp":         false,
		"https://evil.example/":               false,
		"http://gitea.example.com/x":          false,
		"https://gitea.example.com:8443/x":    false,
		"https://user@gitea.example.com/x":    false,
		"https://gitea.example.com.evil.io/x": false,
		"https://gitea.example.com./x":        false,
		"javascript:alert(1)":                 false,
		"":                                    false,
		"//gitea.example.com/x":               false,
		"https://gitea.example.com\\@evil/x":  false,
	} {
		if got := urlElicitationAllowed(res, "example.com", u); got != want {
			t.Errorf("%q: %v, want %v", u, got, want)
		}
	}
}
