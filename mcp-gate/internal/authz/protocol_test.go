package authz

import (
	"net/http"
	"testing"
)

func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

const toolsList = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`

func TestProtocolVersions(t *testing.T) {
	for _, v := range []string{"2025-06-18", "2025-11-25", "2026-07-28"} {
		h := hdr("MCP-Protocol-Version", v, "Mcp-Method", "tools/list")
		got, err := CheckProtocol(h, []byte(toolsList))
		if err != nil || got != v {
			t.Errorf("%s: %q %v", v, got, err)
		}
	}
	for _, v := range []string{"2025-03-26", "2024-11-05", "", "2026-07-28x"} {
		_, err := CheckProtocol(hdr("MCP-Protocol-Version", v), []byte(toolsList))
		if err == nil || err.Status != 400 || err.Msg != "unsupported protocol version" {
			t.Errorf("%q: %+v", v, err)
		}
	}
	// initialize carries its version in the body.
	init := func(v string) []byte {
		return []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` + v + `","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`)
	}
	if got, err := CheckProtocol(http.Header{}, init("2025-11-25")); err != nil || got != "2025-11-25" {
		t.Errorf("initialize 2025-11-25: %q %+v", got, err)
	}
	if _, err := CheckProtocol(http.Header{}, init("2024-11-05")); err == nil || err.Status != 400 || err.Msg != "unsupported protocol version" {
		t.Errorf("initialize 2024-11-05: %+v", err)
	}
	if _, err := CheckProtocol(hdr("MCP-Protocol-Version", "2025-03-26"), init("2025-11-25")); err == nil {
		t.Error("initialize with an unsupported header version accepted")
	}
	// No body (GET stream, DELETE): the header alone.
	if got, err := CheckProtocol(hdr("MCP-Protocol-Version", "2025-06-18"), nil); err != nil || got != "2025-06-18" {
		t.Errorf("no body: %q %+v", got, err)
	}
	// Not JSON-RPC, or a batch.
	for _, b := range []string{`{`, `[` + toolsList + `]`, `{"jsonrpc":"1.0","id":1,"method":"x"}`} {
		if _, err := CheckProtocol(hdr("MCP-Protocol-Version", "2025-11-25"), []byte(b)); err == nil || err.Status != 400 {
			t.Errorf("%s: %+v", b, err)
		}
	}
}

func TestHeaderBodyMismatch(t *testing.T) {
	call := func(name string) []byte {
		return []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"` + name + `","arguments":{}}}`)
	}
	ok := hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/call", "Mcp-Name", "a")
	if _, err := CheckProtocol(ok, call("a")); err != nil {
		t.Fatalf("matching headers: %+v", err)
	}
	for name, c := range map[string]struct {
		h    http.Header
		body []byte
	}{
		"method mismatch": {hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/list"), call("a")},
		"name mismatch":   {hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/call", "Mcp-Name", "a"), call("b")},
		"no method":       {hdr("MCP-Protocol-Version", "2026-07-28"), call("a")},
		"no name":         {hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/call"), call("a")},
		"meta version": {hdr("MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "tools/list"),
			[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}}`)},
	} {
		_, err := CheckProtocol(c.h, c.body)
		if err == nil || err.Status != 400 || err.Code != -32020 {
			t.Errorf("%s: %+v", name, err)
		}
	}
	// Older versions don't carry the headers: no check.
	if _, err := CheckProtocol(hdr("MCP-Protocol-Version", "2025-11-25", "Mcp-Method", "tools/list"), call("a")); err != nil {
		t.Errorf("2025-11-25: %+v", err)
	}
}
