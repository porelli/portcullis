// Package mcpsdk is the one place the gate touches the official MCP Go SDK
// (github.com/modelcontextprotocol/go-sdk, pinned v1.8.0; preflight G18),
// so a later SDK version has one place to change.
package mcpsdk

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"

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

// CallParams decodes tools/call params exactly as the SDK's server does
// (into its own CallToolParamsRaw), after refusing an object whose keys
// repeat, also after case folding (encoding/json matches keys
// case-insensitively and keeps the last), so what the gate logs and
// hashes is what the SDK executes.
func CallParams(params json.RawMessage) (name string, args json.RawMessage, err error) {
	if err := uniqueFoldedKeys(params); err != nil {
		return "", nil, err
	}
	var p mcp.CallToolParamsRaw
	if err := json.Unmarshal(params, &p); err != nil {
		return "", nil, err
	}
	return p.Name, p.Arguments, nil
}

var errKeys = errors.New("params: not one object with distinct keys")

// callFields: folded → exact JSON names of CallToolParamsRaw's fields.
var callFields = func() map[string]string {
	m := map[string]string{}
	var walk func(t reflect.Type)
	walk = func(t reflect.Type) {
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if f.Anonymous && name == "" && f.Type.Kind() == reflect.Struct {
				walk(f.Type)
				continue
			}
			if name == "-" || !f.IsExported() {
				continue
			}
			if name == "" {
				name = f.Name
			}
			m[strings.ToLower(name)] = name
		}
	}
	walk(reflect.TypeOf(mcp.CallToolParamsRaw{}))
	return m
}()

func uniqueFoldedKeys(b json.RawMessage) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return errKeys
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return errKeys
		}
		k, ok := t.(string)
		if !ok {
			return errKeys
		}
		f := strings.ToLower(k)
		if seen[f] {
			return errKeys
		}
		// A key naming one of the SDK's fields must be spelled exactly.
		if exact, known := callFields[f]; known && exact != k {
			return errKeys
		}
		seen[f] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return errKeys
		}
	}
	if _, err := dec.Token(); err != nil {
		return errKeys
	}
	return nil
}

// InitializeVersion is the protocolVersion of an initialize request.
func InitializeVersion(params json.RawMessage) (string, error) {
	var p mcp.InitializeParams
	if err := json.Unmarshal(params, &p); err != nil {
		return "", err
	}
	return p.ProtocolVersion, nil
}
