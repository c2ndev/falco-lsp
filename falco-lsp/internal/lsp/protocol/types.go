// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package protocol

import "encoding/json"

// JSONRPCVersion is the JSON-RPC protocol version used by LSP.
const JSONRPCVersion = "2.0"

// DefaultCompletionTriggerCharacters are the default trigger characters for completion.
// These characters trigger completion suggestions when typed.
var DefaultCompletionTriggerCharacters = []string{".", ":", " ", "[", ",", "-", "="}

// Message represents a JSON-RPC message.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  Method          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *ResponseError  `json:"error,omitempty"`
}

// Method represents an LSP method name.
type Method string

// LSP method constants.
const (
	MethodInitialize                     Method = "initialize"
	MethodInitialized                    Method = "initialized"
	MethodShutdown                       Method = "shutdown"
	MethodExit                           Method = "exit"
	MethodTextDocumentDidOpen            Method = "textDocument/didOpen"
	MethodTextDocumentDidChange          Method = "textDocument/didChange"
	MethodTextDocumentDidClose           Method = "textDocument/didClose"
	MethodTextDocumentDidSave            Method = "textDocument/didSave"
	MethodTextDocumentCompletion         Method = "textDocument/completion"
	MethodTextDocumentHover              Method = "textDocument/hover"
	MethodTextDocumentDefinition         Method = "textDocument/definition"
	MethodTextDocumentReferences         Method = "textDocument/references"
	MethodTextDocumentDocumentSymbol     Method = "textDocument/documentSymbol"
	MethodTextDocumentFormatting         Method = "textDocument/formatting"
	MethodTextDocumentRangeFormatting    Method = "textDocument/rangeFormatting"
	MethodPublishDiagnostics             Method = "textDocument/publishDiagnostics"
	MethodWorkspaceDidChangeWatchedFiles Method = "workspace/didChangeWatchedFiles"
)

// String returns the string representation of the method.
func (m Method) String() string {
	return string(m)
}

// ResponseError represents a JSON-RPC error.
type ResponseError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// LSP error codes.
const (
	ErrorCodeParseError     = -32700
	ErrorCodeInvalidRequest = -32600
	ErrorCodeMethodNotFound = -32601
	ErrorCodeInvalidParams  = -32602
	ErrorCodeInternalError  = -32603
)

// Position represents a position in a text document (0-based).
type Position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

// Range represents a range in a text document.
type Range struct {
	Start Position `json:"start"`
	End   Position `json:"end"`
}

// Location represents a location in a document.
type Location struct {
	URI   string `json:"uri"`
	Range Range  `json:"range"`
}

// TextDocumentIdentifier identifies a text document.
type TextDocumentIdentifier struct {
	URI string `json:"uri"`
}

// VersionedTextDocumentIdentifier identifies a versioned text document.
type VersionedTextDocumentIdentifier struct {
	URI     string `json:"uri"`
	Version int    `json:"version"`
}

// TextDocumentItem represents an open text document.
type TextDocumentItem struct {
	URI        string `json:"uri"`
	LanguageID string `json:"languageId"`
	Version    int    `json:"version"`
	Text       string `json:"text"`
}

// TextDocumentPositionParams contains a text document and a position.
type TextDocumentPositionParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
	Position     Position               `json:"position"`
}

// Diagnostic represents a diagnostic (error, warning, etc.).
type Diagnostic struct {
	Range    Range       `json:"range"`
	Severity int         `json:"severity,omitempty"`
	Code     string      `json:"code,omitempty"`
	Source   string      `json:"source,omitempty"`
	Message  string      `json:"message"`
	Data     interface{} `json:"data,omitempty"`
}

// DiagnosticSeverity constants.
const (
	DiagnosticSeverityError       = 1
	DiagnosticSeverityWarning     = 2
	DiagnosticSeverityInformation = 3
	DiagnosticSeverityHint        = 4
)

// PublishDiagnosticsParams represents the parameters for publishDiagnostics.
type PublishDiagnosticsParams struct {
	URI         string       `json:"uri"`
	Version     *int         `json:"version,omitempty"`
	Diagnostics []Diagnostic `json:"diagnostics"`
}

// InitializeParams represents the initialize request parameters.
type InitializeParams struct {
	ProcessID             int                `json:"processId"`
	RootURI               string             `json:"rootUri"`
	Capabilities          ClientCapabilities `json:"capabilities"`
	InitializationOptions interface{}        `json:"initializationOptions,omitempty"`
}

// ClientCapabilities represents client capabilities.
type ClientCapabilities struct {
	TextDocument TextDocumentClientCapabilities `json:"textDocument,omitempty"`
}

// TextDocumentClientCapabilities represents text document capabilities.
type TextDocumentClientCapabilities struct {
	Completion         CompletionClientCapabilities   `json:"completion,omitempty"`
	PublishDiagnostics PublishDiagnosticsCapabilities `json:"publishDiagnostics,omitempty"`
}

// CompletionClientCapabilities represents completion capabilities.
type CompletionClientCapabilities struct {
	CompletionItem CompletionItemCapabilities `json:"completionItem,omitempty"`
}

// CompletionItemCapabilities represents completion item capabilities.
type CompletionItemCapabilities struct {
	SnippetSupport bool `json:"snippetSupport,omitempty"`
}

// PublishDiagnosticsCapabilities represents publishDiagnostics capabilities.
type PublishDiagnosticsCapabilities struct {
	VersionSupport bool `json:"versionSupport,omitempty"`
}

// InitializeResult represents the initialize response.
type InitializeResult struct {
	Capabilities ServerCapabilities `json:"capabilities"`
	ServerInfo   *ServerInfo        `json:"serverInfo,omitempty"`
}

// ServerCapabilities represents server capabilities.
type ServerCapabilities struct {
	TextDocumentSync                *TextDocumentSyncOptions `json:"textDocumentSync,omitempty"`
	CompletionProvider              *CompletionOptions       `json:"completionProvider,omitempty"`
	HoverProvider                   bool                     `json:"hoverProvider,omitempty"`
	DefinitionProvider              bool                     `json:"definitionProvider,omitempty"`
	ReferencesProvider              bool                     `json:"referencesProvider,omitempty"`
	DocumentSymbolProvider          bool                     `json:"documentSymbolProvider,omitempty"`
	DocumentFormattingProvider      bool                     `json:"documentFormattingProvider,omitempty"`
	DocumentRangeFormattingProvider bool                     `json:"documentRangeFormattingProvider,omitempty"`
}

// TextDocumentSyncOptions represents text document sync options.
type TextDocumentSyncOptions struct {
	OpenClose bool         `json:"openClose"`
	Change    int          `json:"change"`
	Save      *SaveOptions `json:"save,omitempty"`
}

// SaveOptions represents save options.
type SaveOptions struct {
	IncludeText bool `json:"includeText,omitempty"`
}

// TextDocumentSyncKind values.
const (
	TextDocumentSyncKindNone        = 0
	TextDocumentSyncKindFull        = 1
	TextDocumentSyncKindIncremental = 2
)

// CompletionOptions represents completion provider options.
type CompletionOptions struct {
	TriggerCharacters []string `json:"triggerCharacters,omitempty"`
	ResolveProvider   bool     `json:"resolveProvider,omitempty"`
}

// ServerInfo represents server information.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// DidOpenTextDocumentParams represents didOpen parameters.
type DidOpenTextDocumentParams struct {
	TextDocument TextDocumentItem `json:"textDocument"`
}

// DidChangeTextDocumentParams represents didChange parameters.
type DidChangeTextDocumentParams struct {
	TextDocument   VersionedTextDocumentIdentifier  `json:"textDocument"`
	ContentChanges []TextDocumentContentChangeEvent `json:"contentChanges"`
}

// TextDocumentContentChangeEvent represents a content change.
type TextDocumentContentChangeEvent struct {
	Range       *Range `json:"range,omitempty"`
	RangeLength int    `json:"rangeLength,omitempty"`
	Text        string `json:"text"`
}

// DidCloseTextDocumentParams represents didClose parameters.
type DidCloseTextDocumentParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
}

// DidSaveTextDocumentParams represents didSave parameters.
type DidSaveTextDocumentParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
	Text         *string                `json:"text,omitempty"`
}

// DidChangeWatchedFilesParams represents workspace/didChangeWatchedFiles parameters.
type DidChangeWatchedFilesParams struct {
	Changes []FileEvent `json:"changes"`
}

// FileEvent represents a file change event.
type FileEvent struct {
	URI  string `json:"uri"`
	Type int    `json:"type"`
}

// FileChangeType constants.
const (
	FileChangeTypeCreated = 1
	FileChangeTypeChanged = 2
	FileChangeTypeDeleted = 3
)

// CompletionParams represents completion request parameters.
type CompletionParams struct {
	TextDocumentPositionParams
	Context *CompletionContext `json:"context,omitempty"`
}

// CompletionContext represents completion context.
type CompletionContext struct {
	TriggerKind      int    `json:"triggerKind"`
	TriggerCharacter string `json:"triggerCharacter,omitempty"`
}

// CompletionTriggerKind values.
const (
	CompletionTriggerKindInvoked                         = 1
	CompletionTriggerKindTriggerCharacter                = 2
	CompletionTriggerKindTriggerForIncompleteCompletions = 3
)

// CompletionItem represents a completion item.
type CompletionItem struct {
	Label            string    `json:"label"`
	Kind             int       `json:"kind,omitempty"`
	Detail           string    `json:"detail,omitempty"`
	Documentation    string    `json:"documentation,omitempty"`
	InsertText       string    `json:"insertText,omitempty"`
	FilterText       string    `json:"filterText,omitempty"`
	TextEdit         *TextEdit `json:"textEdit,omitempty"`
	InsertTextFormat int       `json:"insertTextFormat,omitempty"`
}

// CompletionItemKind values.
const (
	CompletionItemKindText          = 1
	CompletionItemKindMethod        = 2
	CompletionItemKindFunction      = 3
	CompletionItemKindConstructor   = 4
	CompletionItemKindField         = 5
	CompletionItemKindVariable      = 6
	CompletionItemKindClass         = 7
	CompletionItemKindInterface     = 8
	CompletionItemKindModule        = 9
	CompletionItemKindProperty      = 10
	CompletionItemKindUnit          = 11
	CompletionItemKindValue         = 12
	CompletionItemKindEnum          = 13
	CompletionItemKindKeyword       = 14
	CompletionItemKindSnippet       = 15
	CompletionItemKindColor         = 16
	CompletionItemKindFile          = 17
	CompletionItemKindReference     = 18
	CompletionItemKindFolder        = 19
	CompletionItemKindEnumMember    = 20
	CompletionItemKindConstant      = 21
	CompletionItemKindStruct        = 22
	CompletionItemKindEvent         = 23
	CompletionItemKindOperator      = 24
	CompletionItemKindTypeParameter = 25
)

// InsertTextFormat values.
const (
	InsertTextFormatPlainText = 1
	InsertTextFormatSnippet   = 2
)

// TextEdit represents a text edit.
type TextEdit struct {
	Range   Range  `json:"range"`
	NewText string `json:"newText"`
}

// Hover represents hover information.
type Hover struct {
	Contents MarkupContent `json:"contents"`
	Range    *Range        `json:"range,omitempty"`
}

// MarkupContent represents markup content.
type MarkupContent struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// MarkupKind values.
const (
	MarkupKindPlainText = "plaintext"
	MarkupKindMarkdown  = "markdown"
)

// DocumentFormattingParams represents formatting request parameters.
type DocumentFormattingParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
	Options      FormattingOptions      `json:"options"`
}

// DocumentRangeFormattingParams represents range formatting request parameters.
type DocumentRangeFormattingParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
	Range        Range                  `json:"range"`
	Options      FormattingOptions      `json:"options"`
}

// FormattingOptions represents formatting options.
type FormattingOptions struct {
	TabSize                int  `json:"tabSize"`
	InsertSpaces           bool `json:"insertSpaces"`
	TrimTrailingWhitespace bool `json:"trimTrailingWhitespace,omitempty"`
	InsertFinalNewline     bool `json:"insertFinalNewline,omitempty"`
	TrimFinalNewlines      bool `json:"trimFinalNewlines,omitempty"`
}

// ReferenceParams represents references request parameters.
type ReferenceParams struct {
	TextDocumentPositionParams
	Context ReferenceContext `json:"context"`
}

// ReferenceContext represents references context.
type ReferenceContext struct {
	IncludeDeclaration bool `json:"includeDeclaration"`
}

// DocumentSymbolParams represents document symbol request parameters.
type DocumentSymbolParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
}

// DocumentSymbol represents a symbol in a document.
type DocumentSymbol struct {
	Name           string           `json:"name"`
	Detail         string           `json:"detail,omitempty"`
	Kind           int              `json:"kind"`
	Range          Range            `json:"range"`
	SelectionRange Range            `json:"selectionRange"`
	Children       []DocumentSymbol `json:"children,omitempty"`
}

// SymbolKind values.
const (
	SymbolKindFile          = 1
	SymbolKindModule        = 2
	SymbolKindNamespace     = 3
	SymbolKindPackage       = 4
	SymbolKindClass         = 5
	SymbolKindMethod        = 6
	SymbolKindProperty      = 7
	SymbolKindField         = 8
	SymbolKindConstructor   = 9
	SymbolKindEnum          = 10
	SymbolKindInterface     = 11
	SymbolKindFunction      = 12
	SymbolKindVariable      = 13
	SymbolKindConstant      = 14
	SymbolKindString        = 15
	SymbolKindNumber        = 16
	SymbolKindBoolean       = 17
	SymbolKindArray         = 18
	SymbolKindObject        = 19
	SymbolKindKey           = 20
	SymbolKindNull          = 21
	SymbolKindEnumMember    = 22
	SymbolKindStruct        = 23
	SymbolKindEvent         = 24
	SymbolKindOperator      = 25
	SymbolKindTypeParameter = 26
)

// NullResult is a sentinel value that serializes to JSON null.
// Use this when a response requires an explicit null result (e.g., shutdown).
type NullResult struct{}

// MarshalJSON implements json.Marshaler for NullResult.
func (NullResult) MarshalJSON() ([]byte, error) {
	return []byte("null"), nil
}

// NewResponse creates a new JSON-RPC response message.
func NewResponse(id, result interface{}) *Message {
	return &Message{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Result:  result,
	}
}

// NewNullResponse creates a new JSON-RPC response with explicit null result.
// This is required for methods like shutdown that must return null.
func NewNullResponse(id interface{}) *Message {
	return &Message{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Result:  NullResult{},
	}
}

// NewErrorResponse creates a new JSON-RPC error response message.
func NewErrorResponse(id interface{}, code int, message string) *Message {
	return &Message{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Error: &ResponseError{
			Code:    code,
			Message: message,
		},
	}
}

// NewNotification creates a new JSON-RPC notification message.
func NewNotification(method Method, params json.RawMessage) *Message {
	return &Message{
		JSONRPC: JSONRPCVersion,
		Method:  method,
		Params:  params,
	}
}
