package authz

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/portcullis/mcp-gate/internal/config"
	"github.com/portcullis/mcp-gate/internal/mcpsdk"
)

// ProtocolError is a 400 with a JSON-RPC error code.
type ProtocolError struct {
	Status int
	Code   int
	Msg    string
}

func (e *ProtocolError) Error() string { return e.Msg }

const versionWithHeaders = "2026-07-28"

func unsupported() *ProtocolError {
	return &ProtocolError{http.StatusBadRequest, mcpsdk.CodeUnsupportedProtocolVersion, "unsupported protocol version"}
}

func mismatch(msg string) *ProtocolError {
	return &ProtocolError{http.StatusBadRequest, mcpsdk.CodeHeaderMismatch, msg}
}

// CheckProtocol checks a raw MCP request (contract §15.3): the version
// from MCP-Protocol-Version or, for initialize, the body's
// protocolVersion, must be one the gate supports; on 2026-07-28 the
// Mcp-Method / Mcp-Name headers must match the body (-32020). body may be
// empty (a GET stream or a DELETE): then only the header counts. Callers
// decide on the parsed body, never the headers. It runs on bodies the
// gate proxies raw (preflight G25); requests the gate serves through the
// SDK server get the SDK's own checks (G18).
func CheckProtocol(h http.Header, body []byte) (version string, err *ProtocolError) {
	header := h.Get("MCP-Protocol-Version")
	if len(h.Values("MCP-Protocol-Version")) > 1 {
		return "", unsupported()
	}
	if header != "" && !slices.Contains(config.SupportedProtocols, header) {
		return "", unsupported()
	}
	if len(body) == 0 {
		if header == "" {
			return "", unsupported()
		}
		return header, nil
	}
	msg, derr := mcpsdk.Decode(body)
	if derr != nil {
		return "", &ProtocolError{http.StatusBadRequest, mcpsdk.CodeParseError, "not a JSON-RPC message"}
	}
	version = header
	if msg.IsRequest && msg.Method == "initialize" {
		v, err := mcpsdk.InitializeVersion(msg.Params)
		if err != nil || !slices.Contains(config.SupportedProtocols, v) {
			return "", unsupported()
		}
		if header != "" && header != v {
			return "", mismatch("MCP-Protocol-Version does not match initialize's protocolVersion")
		}
		version = v
	}
	if version == "" {
		return "", unsupported()
	}
	if !msg.IsRequest {
		return version, nil
	}
	// _meta protocolVersion (SEP-2575) must match the effective version.
	var p struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if len(msg.Params) > 0 && json.Unmarshal(msg.Params, &p) == nil {
		if raw, ok := p.Meta[mcpsdk.MetaKeyProtocolVersion]; ok {
			var mv string
			if json.Unmarshal(raw, &mv) != nil || mv != version {
				return "", mismatch("the protocol version does not match _meta protocolVersion")
			}
		}
	}
	if version != versionWithHeaders {
		return version, nil
	}
	if len(h.Values("Mcp-Method")) != 1 || h.Get("Mcp-Method") != msg.Method {
		return "", mismatch("Mcp-Method header missing or does not match the body")
	}
	name, named, nerr := mcpsdk.Name(msg.Method, msg.Params)
	if named {
		if nerr != nil || len(h.Values("Mcp-Name")) != 1 || h.Get("Mcp-Name") != name {
			return "", mismatch("Mcp-Name header missing or does not match the body")
		}
	}
	return version, nil
}
