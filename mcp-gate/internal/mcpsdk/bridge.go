package mcpsdk

// Aliases for the bridge (plan 4 task 3): the bridge is an SDK server
// facing the person's client and an SDK client per upstream session, so it
// uses the SDK's types directly — but only through these names, so a later
// SDK version still has one place to change (G18).

import (
	"encoding/json"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type (
	Tool                        = mcp.Tool
	ToolAnnotations             = mcp.ToolAnnotations
	Server                      = mcp.Server
	ServerOptions               = mcp.ServerOptions
	ServerSession               = mcp.ServerSession
	ServerCapabilities          = mcp.ServerCapabilities
	ToolCapabilities            = mcp.ToolCapabilities
	ResourceCapabilities        = mcp.ResourceCapabilities
	PromptCapabilities          = mcp.PromptCapabilities
	Client                      = mcp.Client
	ClientOptions               = mcp.ClientOptions
	ClientSession               = mcp.ClientSession
	ClientSessionOptions        = mcp.ClientSessionOptions
	ClientCapabilities          = mcp.ClientCapabilities
	ElicitationCapabilities     = mcp.ElicitationCapabilities
	FormElicitationCapabilities = mcp.FormElicitationCapabilities
	URLElicitationCapabilities  = mcp.URLElicitationCapabilities
	MultiRoundTripOptions       = mcp.MultiRoundTripOptions
	Implementation              = mcp.Implementation
	StreamableHTTPHandler       = mcp.StreamableHTTPHandler
	StreamableHTTPOptions       = mcp.StreamableHTTPOptions
	StreamableClientTransport   = mcp.StreamableClientTransport
	Middleware                  = mcp.Middleware
	MethodHandler               = mcp.MethodHandler
	Request                     = mcp.Request
	Result                      = mcp.Result
	CallToolParams              = mcp.CallToolParams
	CallToolParamsRaw           = mcp.CallToolParamsRaw
	CallToolResult              = mcp.CallToolResult
	CallToolRequest             = mcp.CallToolRequest
	ListToolsParams             = mcp.ListToolsParams
	ListToolsResult             = mcp.ListToolsResult
	ListResourcesParams         = mcp.ListResourcesParams
	ListResourcesResult         = mcp.ListResourcesResult
	ListResourceTemplatesParams = mcp.ListResourceTemplatesParams
	ListResourceTemplatesResult = mcp.ListResourceTemplatesResult
	ReadResourceParams          = mcp.ReadResourceParams
	ReadResourceResult          = mcp.ReadResourceResult
	ListPromptsParams           = mcp.ListPromptsParams
	ListPromptsResult           = mcp.ListPromptsResult
	GetPromptParams             = mcp.GetPromptParams
	GetPromptResult             = mcp.GetPromptResult
	ElicitParams                = mcp.ElicitParams
	ElicitRequest               = mcp.ElicitRequest
	ElicitResult                = mcp.ElicitResult
	InputRequest                = mcp.InputRequest
	InputRequestMap             = mcp.InputRequestMap
	InputResponse               = mcp.InputResponse
	InputResponseMap            = mcp.InputResponseMap
	CreateMessageParams         = mcp.CreateMessageParams
	CreateMessageResult         = mcp.CreateMessageResult
	ListRootsParams             = mcp.ListRootsParams
	ListRootsResult             = mcp.ListRootsResult
	Content                     = mcp.Content
	TextContent                 = mcp.TextContent
	Meta                        = mcp.Meta
	ToolListChangedRequest      = mcp.ToolListChangedRequest
	TokenInfo                   = auth.TokenInfo
	Resource                    = mcp.Resource
	ResourceTemplate            = mcp.ResourceTemplate
	Prompt                      = mcp.Prompt
	RequestExtra                = mcp.RequestExtra
	RPCError                    = jsonrpc.Error
)

// Method names and error codes the bridge uses.
const (
	MethodInitialize            = "initialize"
	MethodListTools             = "tools/list"
	MethodCallTool              = "tools/call"
	MethodListResources         = "resources/list"
	MethodListResourceTemplates = "resources/templates/list"
	MethodReadResource          = "resources/read"
	MethodListPrompts           = "prompts/list"
	MethodGetPrompt             = "prompts/get"
	MethodComplete              = "completion/complete"
	MethodSubscribe             = "resources/subscribe"
	MethodUnsubscribe           = "resources/unsubscribe"
	MethodCreateMessage         = "sampling/createMessage"
	MethodListRoots             = "roots/list"
	MethodElicit                = "elicitation/create"

	CodeMethodNotFound = jsonrpc.CodeMethodNotFound
	CodeInvalidParams  = jsonrpc.CodeInvalidParams
	CodeInternalError  = jsonrpc.CodeInternalError

	// ProtocolStateless is the first sessionless version (SEP-2575).
	ProtocolStateless = "2026-07-28"
)

var (
	NewServer                = mcp.NewServer
	NewClient                = mcp.NewClient
	NewStreamableHTTPHandler = mcp.NewStreamableHTTPHandler
	RequireBearerToken       = auth.RequireBearerToken
	TokenInfoFromContext     = auth.TokenInfoFromContext
	ErrConnectionClosed      = mcp.ErrConnectionClosed
	SupportedSDKProtocols    = mcp.SupportedProtocolVersions
	MetaKeyServerInfo        = mcp.MetaKeyServerInfo
)

// ProtocolSessionElicitURL is the one session protocol version with
// URL-mode elicitation/create (2025-06-18 has none; 2026-07-28 asks through
// input_required results instead).
const ProtocolSessionElicitURL = "2025-11-25"

// InputRequired is a tools/call result of resultType "input_required"
// (SEP-2322) carrying reqs and the opaque state the client echoes back.
// The SDK keeps the result type unexported, so it is built through the
// SDK's own decoder.
func InputRequired(reqs InputRequestMap, state string) (*CallToolResult, error) {
	if len(reqs) == 0 {
		return nil, errors.New("input_required without input requests")
	}
	b, err := json.Marshal(struct {
		ResultType    string          `json:"resultType"`
		InputRequests InputRequestMap `json:"inputRequests"`
		RequestState  string          `json:"requestState,omitempty"`
	}{"input_required", reqs, state})
	if err != nil {
		return nil, err
	}
	var r CallToolResult
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if !r.NeedsInput() || len(r.InputRequests) != len(reqs) || r.RequestState != state {
		return nil, errors.New("input_required result did not round-trip")
	}
	return &r, nil
}
