// Package mcpsdk is the one place the gate touches the official MCP Go SDK
// (github.com/modelcontextprotocol/go-sdk, pinned v1.8.0; preflight G18),
// so a later SDK version has one place to change.
package mcpsdk

import (
	"encoding/json"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// JSON-RPC / MCP error codes.
const (
	CodeParseError                 = jsonrpc.CodeParseError
	CodeInvalidRequest             = jsonrpc.CodeInvalidRequest
	CodeHeaderMismatch             = mcp.CodeHeaderMismatch // -32020
	CodeUnsupportedProtocolVersion = mcp.CodeUnsupportedProtocolVersion
)

// MetaKeyProtocolVersion is the per-request _meta protocol version key.
const MetaKeyProtocolVersion = mcp.MetaKeyProtocolVersion

// Message is a decoded JSON-RPC message.
type Message struct {
	IsRequest bool   // a request or notification (has a method)
	Method    string // requests only
	Params    json.RawMessage
}

// Decode parses one JSON-RPC message (no batches) with the SDK's codec.
func Decode(body []byte) (*Message, error) {
	msg, err := jsonrpc.DecodeMessage(body)
	if err != nil {
		return nil, err
	}
	switch m := msg.(type) {
	case *jsonrpc.Request:
		return &Message{IsRequest: true, Method: m.Method, Params: m.Params}, nil
	case *jsonrpc.Response:
		return &Message{}, nil
	}
	return nil, errors.New("unknown message")
}

// Name is the Mcp-Name a request's body carries: the tool or prompt
// name, or the resource URI. ok is false for other methods.
func Name(method string, params json.RawMessage) (name string, ok bool, err error) {
	switch method {
	case "tools/call":
		var p mcp.CallToolParams
		err = json.Unmarshal(params, &p)
		return p.Name, true, err
	case "prompts/get":
		var p mcp.GetPromptParams
		err = json.Unmarshal(params, &p)
		return p.Name, true, err
	case "resources/read":
		var p mcp.ReadResourceParams
		err = json.Unmarshal(params, &p)
		return p.URI, true, err
	}
	return "", false, nil
}

// InitializeVersion is the protocolVersion of an initialize request.
func InitializeVersion(params json.RawMessage) (string, error) {
	var p mcp.InitializeParams
	if err := json.Unmarshal(params, &p); err != nil {
		return "", err
	}
	return p.ProtocolVersion, nil
}
