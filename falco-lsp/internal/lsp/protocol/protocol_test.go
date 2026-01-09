// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Alessandro Cannarella
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

// Package protocol provides LSP protocol types and utilities.
package protocol

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

// testMultiLineContent is used across multiple tests for position/offset conversion.
const testMultiLineContent = "line one\nline two\nline three"

func TestMethod_String(t *testing.T) {
	tests := []struct {
		method   Method
		expected string
	}{
		{MethodInitialize, "initialize"},
		{MethodInitialized, "initialized"},
		{MethodShutdown, "shutdown"},
		{MethodTextDocumentDidOpen, "textDocument/didOpen"},
		{MethodTextDocumentCompletion, "textDocument/completion"},
		{MethodTextDocumentHover, "textDocument/hover"},
		{MethodTextDocumentDefinition, "textDocument/definition"},
		{MethodTextDocumentFormatting, "textDocument/formatting"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.method.String())
		})
	}
}

func TestDiagnosticSeverityConstants(t *testing.T) {
	// Verify severity constants match LSP spec
	assert.Equal(t, 1, DiagnosticSeverityError)
	assert.Equal(t, 2, DiagnosticSeverityWarning)
	assert.Equal(t, 3, DiagnosticSeverityInformation)
	assert.Equal(t, 4, DiagnosticSeverityHint)
}

func TestErrorCodeConstants(t *testing.T) {
	// Verify error codes match JSON-RPC spec
	assert.Equal(t, -32700, ErrorCodeParseError)
	assert.Equal(t, -32600, ErrorCodeInvalidRequest)
	assert.Equal(t, -32601, ErrorCodeMethodNotFound)
	assert.Equal(t, -32602, ErrorCodeInvalidParams)
	assert.Equal(t, -32603, ErrorCodeInternalError)
}

func TestTextDocumentSyncKindConstants(t *testing.T) {
	assert.Equal(t, 0, TextDocumentSyncKindNone)
	assert.Equal(t, 1, TextDocumentSyncKindFull)
	assert.Equal(t, 2, TextDocumentSyncKindIncremental)
}

func TestCompletionItemKindConstants(t *testing.T) {
	// These constants should exist and have standard LSP values
	assert.Equal(t, 1, CompletionItemKindText)
	assert.Equal(t, 2, CompletionItemKindMethod)
	assert.Equal(t, 3, CompletionItemKindFunction)
	assert.Equal(t, 6, CompletionItemKindVariable)
	assert.Equal(t, 7, CompletionItemKindClass)
	assert.Equal(t, 15, CompletionItemKindSnippet)
	assert.Equal(t, 21, CompletionItemKindConstant)
}

func TestSymbolKindConstants(t *testing.T) {
	assert.Equal(t, 5, SymbolKindClass)
	assert.Equal(t, 12, SymbolKindFunction)
	assert.Equal(t, 13, SymbolKindVariable)
	assert.Equal(t, 14, SymbolKindConstant)
}

func TestPosition(t *testing.T) {
	pos := Position{Line: 10, Character: 5}
	assert.Equal(t, 10, pos.Line)
	assert.Equal(t, 5, pos.Character)
}

func TestRange(t *testing.T) {
	r := Range{
		Start: Position{Line: 0, Character: 0},
		End:   Position{Line: 0, Character: 10},
	}
	assert.Equal(t, 0, r.Start.Line)
	assert.Equal(t, 10, r.End.Character)
}

func TestLocation(t *testing.T) {
	loc := Location{
		URI: "file:///test.yaml",
		Range: Range{
			Start: Position{Line: 5, Character: 0},
			End:   Position{Line: 5, Character: 20},
		},
	}
	assert.Equal(t, "file:///test.yaml", loc.URI)
	assert.Equal(t, 5, loc.Range.Start.Line)
}

func TestTextDocumentIdentifier(t *testing.T) {
	tdi := TextDocumentIdentifier{URI: "file:///rules.yaml"}
	assert.Equal(t, "file:///rules.yaml", tdi.URI)
}

func TestVersionedTextDocumentIdentifier(t *testing.T) {
	vtdi := VersionedTextDocumentIdentifier{
		URI:     "file:///rules.yaml",
		Version: 42,
	}
	assert.Equal(t, "file:///rules.yaml", vtdi.URI)
	assert.Equal(t, 42, vtdi.Version)
}

func TestTextDocumentItem(t *testing.T) {
	tdi := TextDocumentItem{
		URI:        "file:///rules.yaml",
		LanguageID: "falco-yaml",
		Version:    1,
		Text:       "- rule: Test",
	}
	assert.Equal(t, "file:///rules.yaml", tdi.URI)
	assert.Equal(t, "falco-yaml", tdi.LanguageID)
	assert.Equal(t, 1, tdi.Version)
	assert.Equal(t, "- rule: Test", tdi.Text)
}

func TestDiagnostic(t *testing.T) {
	diag := Diagnostic{
		Range: Range{
			Start: Position{Line: 0, Character: 0},
			End:   Position{Line: 0, Character: 10},
		},
		Severity: DiagnosticSeverityError,
		Code:     "E001",
		Source:   "falco-lang",
		Message:  "Unknown field",
	}

	assert.Equal(t, DiagnosticSeverityError, diag.Severity)
	assert.Equal(t, "E001", diag.Code)
	assert.Equal(t, "falco-lang", diag.Source)
	assert.Equal(t, "Unknown field", diag.Message)
}

func TestResponseError(t *testing.T) {
	err := ResponseError{
		Code:    ErrorCodeInvalidParams,
		Message: "Invalid parameters",
		Data:    map[string]string{"field": "uri"},
	}

	assert.Equal(t, ErrorCodeInvalidParams, err.Code)
	assert.Equal(t, "Invalid parameters", err.Message)
	assert.Equal(t, map[string]string{"field": "uri"}, err.Data)
}

func TestServerCapabilities(t *testing.T) {
	caps := ServerCapabilities{
		HoverProvider:              true,
		DefinitionProvider:         true,
		ReferencesProvider:         true,
		DocumentSymbolProvider:     true,
		DocumentFormattingProvider: true,
		CompletionProvider: &CompletionOptions{
			TriggerCharacters: []string{".", "-", " "},
		},
	}

	assert.True(t, caps.HoverProvider)
	assert.True(t, caps.DefinitionProvider)
	assert.True(t, caps.ReferencesProvider)
	assert.True(t, caps.DocumentSymbolProvider)
	assert.True(t, caps.DocumentFormattingProvider)
	assert.NotNil(t, caps.CompletionProvider)
	assert.Contains(t, caps.CompletionProvider.TriggerCharacters, "-")
}

func TestDiagnosticSerialization(t *testing.T) {
	diagnostic := Diagnostic{
		Range: Range{
			Start: Position{Line: 0, Character: 0},
			End:   Position{Line: 0, Character: 10},
		},
		Severity: DiagnosticSeverityError,
		Code:     "test-error",
		Source:   "falco",
		Message:  "Test error message",
	}

	data, err := json.Marshal(diagnostic)
	if err != nil {
		t.Fatalf("failed to marshal diagnostic: %v", err)
	}

	var unmarshaled Diagnostic
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal diagnostic: %v", err)
	}

	assert.Equal(t, diagnostic.Message, unmarshaled.Message)
	assert.Equal(t, diagnostic.Severity, unmarshaled.Severity)
}

func TestCompletionItemSerialization(t *testing.T) {
	item := CompletionItem{
		Label:            "rule",
		Kind:             CompletionItemKindClass,
		Detail:           "Define a detection rule",
		InsertText:       "- rule: ",
		InsertTextFormat: InsertTextFormatPlainText,
	}

	data, err := json.Marshal(item)
	if err != nil {
		t.Fatalf("failed to marshal completion item: %v", err)
	}

	var unmarshaled CompletionItem
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal completion item: %v", err)
	}

	assert.Equal(t, item.Label, unmarshaled.Label)
	assert.Equal(t, item.Kind, unmarshaled.Kind)
}

func TestPositionToOffset(t *testing.T) {
	tests := []struct {
		pos      Position
		expected int
	}{
		{Position{Line: 0, Character: 0}, 0},
		{Position{Line: 0, Character: 4}, 4},
		{Position{Line: 1, Character: 0}, 9},
		{Position{Line: 1, Character: 4}, 13},
		{Position{Line: 2, Character: 0}, 18},
		// Beyond line end should clamp to line end
		{Position{Line: 0, Character: 100}, 8},
	}

	for _, tt := range tests {
		got := PositionToOffset(testMultiLineContent, tt.pos)
		assert.Equal(t, tt.expected, got, "PositionToOffset at %+v", tt.pos)
	}
}

func TestOffsetToPosition(t *testing.T) {
	tests := []struct {
		offset   int
		expected Position
	}{
		{0, Position{Line: 0, Character: 0}},
		{4, Position{Line: 0, Character: 4}},
		{9, Position{Line: 1, Character: 0}},
		{13, Position{Line: 1, Character: 4}},
		{18, Position{Line: 2, Character: 0}},
		// Negative offset
		{-5, Position{Line: 0, Character: 0}},
	}

	for _, tt := range tests {
		got := OffsetToPosition(testMultiLineContent, tt.offset)
		assert.Equal(t, tt.expected, got, "OffsetToPosition(%d)", tt.offset)
	}
}

func TestLineCount(t *testing.T) {
	tests := []struct {
		content  string
		expected int
	}{
		{"", 0},
		{"single line", 1},
		{"line one\nline two", 2},
		{"line one\nline two\nline three", 3},
		{"line one\n", 2}, // Trailing newline creates empty line
	}

	for _, tt := range tests {
		got := LineCount(tt.content)
		assert.Equal(t, tt.expected, got, "LineCount(%q)", tt.content)
	}
}

func TestGetLine(t *testing.T) {
	tests := []struct {
		line     int
		expected string
	}{
		{0, "line one"},
		{1, "line two"},
		{2, "line three"},
		{-1, ""},
		{100, ""},
	}

	for _, tt := range tests {
		got := GetLine(testMultiLineContent, tt.line)
		assert.Equal(t, tt.expected, got, "GetLine(content, %d)", tt.line)
	}
}

func TestGetLines(t *testing.T) {
	lines := GetLines(testMultiLineContent)

	assert.Len(t, lines, 3)
	assert.Equal(t, "line one", lines[0])
	assert.Equal(t, "line two", lines[1])
	assert.Equal(t, "line three", lines[2])
}

func TestNewResponse(t *testing.T) {
	result := map[string]string{"key": "value"}
	msg := NewResponse(1, result)

	assert.Equal(t, JSONRPCVersion, msg.JSONRPC)
	assert.Equal(t, 1, msg.ID)
	assert.Equal(t, result, msg.Result)
	assert.Nil(t, msg.Error)
}

func TestNewErrorResponse(t *testing.T) {
	msg := NewErrorResponse(1, ErrorCodeInvalidParams, "invalid params")

	assert.Equal(t, JSONRPCVersion, msg.JSONRPC)
	assert.Equal(t, 1, msg.ID)
	assert.Nil(t, msg.Result)
	assert.NotNil(t, msg.Error)
	assert.Equal(t, ErrorCodeInvalidParams, msg.Error.Code)
	assert.Equal(t, "invalid params", msg.Error.Message)
}

func TestNewNotification(t *testing.T) {
	params := json.RawMessage(`{"key":"value"}`)
	msg := NewNotification(MethodPublishDiagnostics, params)

	assert.Equal(t, JSONRPCVersion, msg.JSONRPC)
	assert.Nil(t, msg.ID)
	assert.Equal(t, MethodPublishDiagnostics, msg.Method)
	assert.Equal(t, params, msg.Params)
}

func TestMarkupKindConstants(t *testing.T) {
	assert.Equal(t, "plaintext", MarkupKindPlainText)
	assert.Equal(t, "markdown", MarkupKindMarkdown)
}

func TestInsertTextFormatConstants(t *testing.T) {
	assert.Equal(t, 1, InsertTextFormatPlainText)
	assert.Equal(t, 2, InsertTextFormatSnippet)
}

func TestCompletionTriggerKindConstants(t *testing.T) {
	assert.Equal(t, 1, CompletionTriggerKindInvoked)
	assert.Equal(t, 2, CompletionTriggerKindTriggerCharacter)
	assert.Equal(t, 3, CompletionTriggerKindTriggerForIncompleteCompletions)
}

func TestDefaultCompletionTriggerCharacters(t *testing.T) {
	// Ensure default trigger characters are defined
	assert.NotEmpty(t, DefaultCompletionTriggerCharacters)
	assert.Contains(t, DefaultCompletionTriggerCharacters, ".")
	assert.Contains(t, DefaultCompletionTriggerCharacters, ":")
}

func TestMessageSerialization(t *testing.T) {
	msg := &Message{
		JSONRPC: JSONRPCVersion,
		ID:      1,
		Method:  MethodInitialize,
		Params:  json.RawMessage(`{"capabilities":{}}`),
	}

	data, err := json.Marshal(msg)
	assert.NoError(t, err)

	var unmarshaled Message
	err = json.Unmarshal(data, &unmarshaled)
	assert.NoError(t, err)

	assert.Equal(t, msg.JSONRPC, unmarshaled.JSONRPC)
	assert.Equal(t, float64(1), unmarshaled.ID) // JSON unmarshals numbers as float64
	assert.Equal(t, msg.Method, unmarshaled.Method)
}

func TestHoverSerialization(t *testing.T) {
	hover := Hover{
		Contents: MarkupContent{
			Kind:  MarkupKindMarkdown,
			Value: "**test**",
		},
		Range: &Range{
			Start: Position{Line: 0, Character: 0},
			End:   Position{Line: 0, Character: 4},
		},
	}

	data, err := json.Marshal(hover)
	assert.NoError(t, err)

	var unmarshaled Hover
	err = json.Unmarshal(data, &unmarshaled)
	assert.NoError(t, err)

	assert.Equal(t, hover.Contents.Kind, unmarshaled.Contents.Kind)
	assert.Equal(t, hover.Contents.Value, unmarshaled.Contents.Value)
	assert.NotNil(t, unmarshaled.Range)
}

func TestDocumentSymbolSerialization(t *testing.T) {
	symbol := DocumentSymbol{
		Name:           "test_rule",
		Kind:           SymbolKindClass,
		Detail:         "A test rule",
		Range:          Range{Start: Position{0, 0}, End: Position{5, 0}},
		SelectionRange: Range{Start: Position{0, 8}, End: Position{0, 17}},
		Children:       []DocumentSymbol{},
	}

	data, err := json.Marshal(symbol)
	assert.NoError(t, err)

	var unmarshaled DocumentSymbol
	err = json.Unmarshal(data, &unmarshaled)
	assert.NoError(t, err)

	assert.Equal(t, symbol.Name, unmarshaled.Name)
	assert.Equal(t, symbol.Kind, unmarshaled.Kind)
}

func TestTextEditSerialization(t *testing.T) {
	edit := TextEdit{
		Range: Range{
			Start: Position{Line: 0, Character: 0},
			End:   Position{Line: 0, Character: 10},
		},
		NewText: "replacement",
	}

	data, err := json.Marshal(edit)
	assert.NoError(t, err)

	var unmarshaled TextEdit
	err = json.Unmarshal(data, &unmarshaled)
	assert.NoError(t, err)

	assert.Equal(t, edit.NewText, unmarshaled.NewText)
	assert.Equal(t, edit.Range.Start.Character, unmarshaled.Range.Start.Character)
}

func TestPublishDiagnosticsParamsSerialization(t *testing.T) {
	version := 1
	params := PublishDiagnosticsParams{
		URI:     "file:///test.yaml",
		Version: &version,
		Diagnostics: []Diagnostic{
			{
				Range:    Range{Start: Position{0, 0}, End: Position{0, 5}},
				Severity: DiagnosticSeverityError,
				Message:  "test error",
			},
		},
	}

	data, err := json.Marshal(params)
	assert.NoError(t, err)

	var unmarshaled PublishDiagnosticsParams
	err = json.Unmarshal(data, &unmarshaled)
	assert.NoError(t, err)

	assert.Equal(t, params.URI, unmarshaled.URI)
	assert.NotNil(t, unmarshaled.Version)
	assert.Len(t, unmarshaled.Diagnostics, 1)
}
