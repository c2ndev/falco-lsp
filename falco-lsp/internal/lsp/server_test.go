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

// Package lsp provides the Language Server Protocol implementation.
package lsp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falco-lsp/internal/analyzer"
	"github.com/falcosecurity/falco-lsp/internal/lsp/document"
	"github.com/falcosecurity/falco-lsp/internal/lsp/protocol"
	"github.com/falcosecurity/falco-lsp/internal/lsp/transport"
	"github.com/falcosecurity/falco-lsp/internal/parser"
)

// Test content constants to avoid repetition.
const testMacroRuleContent = `- macro: is_shell
  condition: proc.name in (bash, sh)

- rule: Shell Spawn
  desc: Test
  condition: is_shell
  output: "shell"
  priority: INFO
`

// testBasicRuleContent is a basic rule content used across multiple server tests.
const testBasicRuleContent = `- rule: Test
  desc: Test
  condition: evt.type = open
  output: "test"
  priority: INFO
`

// analyzeDocument analyzes a document and populates its Symbols field.
// This helper is used in tests to simulate what the diagnostics provider does.
func analyzeDocument(doc *document.Document) {
	if doc.Result == nil || doc.Result.Document == nil {
		return
	}
	a := analyzer.NewAnalyzer()
	result := a.Analyze(doc.Result.Document, doc.URI)
	doc.Symbols = result.Symbols
}

// testDocumentURI is the default URI used in tests.
const testDocumentURI = "file:///test.yaml"

// openDocumentForTest opens a document in the server for testing purposes.
// This helper reduces duplication in tests that need to open a document before testing.
func openDocumentForTest(server *Server, content string) {
	openParams := protocol.DidOpenTextDocumentParams{
		TextDocument: protocol.TextDocumentItem{
			URI:     testDocumentURI,
			Version: 1,
			Text:    content,
		},
	}
	openBytes, _ := json.Marshal(openParams)
	server.handleMessage(&protocol.Message{
		JSONRPC: "2.0",
		Method:  protocol.MethodTextDocumentDidOpen,
		Params:  openBytes,
	})
}

func TestNewServer(t *testing.T) {
	server := NewServer()

	require.NotNil(t, server, "NewServer returned nil")
	assert.NotNil(t, server.Documents(), "documents should not be nil")
	assert.NotNil(t, server.Completion(), "completion should not be nil")
	assert.NotNil(t, server.Hover(), "hover should not be nil")
	assert.NotNil(t, server.Definition(), "definition should not be nil")
	assert.NotNil(t, server.Symbols(), "symbols should not be nil")
	assert.NotNil(t, server.References(), "references should not be nil")
	assert.NotNil(t, server.Formatting(), "formatting should not be nil")
}

func TestDocumentStoreIntegration(t *testing.T) {
	server := NewServer()

	// Test document store operations
	content := "- rule: Test\n  desc: test\n"
	result, _ := parser.Parse(content, "test.yaml")
	testDoc := &document.Document{
		URI:     "test.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}
	_ = server.Documents().Set(testDoc)

	// Should be found
	doc, ok := server.Documents().Get("test.yaml")
	assert.True(t, ok, "expected document to be found")
	assert.Equal(t, "test.yaml", doc.URI, "expected URI 'test.yaml'")

	// Delete it
	server.Documents().Delete("test.yaml")
	_, ok = server.Documents().Get("test.yaml")
	assert.False(t, ok, "document should be deleted")
}

func TestServerCompletionIntegration(_ *testing.T) {
	server := NewServer()

	content := `- rule: Test Rule
  desc: Test
  condition: evt.
  output: "test"
  priority: INFO
`
	result, _ := parser.Parse(content, "test.yaml")
	doc := &document.Document{
		URI:     "test.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}
	_ = server.Documents().Set(doc)

	// Use completion provider directly
	params := protocol.CompletionParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: "test.yaml"},
			Position:     protocol.Position{Line: 2, Character: 16}, // After "evt."
		},
	}

	items := server.Completion().GetCompletions(doc, params)
	// May return empty for partial match
	_ = items
}

func TestServerHoverIntegration(_ *testing.T) {
	server := NewServer()

	content := `- rule: Test Rule
  desc: Test
  condition: evt.type = open
  output: "test"
  priority: INFO
`
	result, _ := parser.Parse(content, "test.yaml")
	doc := &document.Document{
		URI:     "test.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}
	_ = server.Documents().Set(doc)

	params := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "test.yaml"},
		Position:     protocol.Position{Line: 2, Character: 14}, // On "evt.type"
	}

	hover := server.Hover().GetHover(doc, params)
	_ = hover
}

func TestServerDefinitionIntegration(_ *testing.T) {
	server := NewServer()

	result, _ := parser.Parse(testMacroRuleContent, "test.yaml")
	doc := &document.Document{
		URI:     "test.yaml",
		Content: testMacroRuleContent,
		Version: 1,
		Result:  result,
	}
	_ = server.Documents().Set(doc)

	// Analyze to register the macro
	analyzeDocument(doc)

	params := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "test.yaml"},
		Position:     protocol.Position{Line: 5, Character: 14}, // On "is_shell"
	}

	location := server.Definition().GetDefinition(doc, params)
	_ = location
}

func TestServerDocumentSymbolIntegration(t *testing.T) {
	server := NewServer()

	result, _ := parser.Parse(testMacroRuleContent, "test.yaml")
	doc := &document.Document{
		URI:     "test.yaml",
		Content: testMacroRuleContent,
		Version: 1,
		Result:  result,
	}
	_ = server.Documents().Set(doc)

	// Analyze document to populate symbols
	analyzeDocument(doc)

	symbols := server.Symbols().GetDocumentSymbols(doc)

	assert.NotEmpty(t, symbols, "expected symbols to be returned")
}

func TestServerReferencesIntegration(_ *testing.T) {
	server := NewServer()

	content := `- macro: is_shell
  condition: proc.name in (bash, sh)

- rule: Shell Spawn
  desc: Test
  condition: is_shell and evt.type = execve
  output: "shell"
  priority: INFO
`
	result, _ := parser.Parse(content, "test.yaml")
	doc := &document.Document{
		URI:     "test.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}
	_ = server.Documents().Set(doc)

	analyzeDocument(doc)

	params := protocol.ReferenceParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: "test.yaml"},
			Position:     protocol.Position{Line: 0, Character: 10}, // On "is_shell"
		},
		Context: protocol.ReferenceContext{IncludeDeclaration: true},
	}

	refs := server.References().GetReferences(doc, params)
	// Should find at least the declaration
	_ = refs
}

func TestServerFormattingIntegration(_ *testing.T) {
	server := NewServer()

	content := `- rule: Test
  desc: test
  condition: evt.type = open
  output: "test"
  priority: INFO
`
	result, _ := parser.Parse(content, "test.yaml")
	doc := &document.Document{
		URI:     "test.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}
	_ = server.Documents().Set(doc)

	opts := protocol.FormattingOptions{
		TabSize:      2,
		InsertSpaces: true,
	}

	edits := server.Formatting().Format(doc, opts)
	// Should return edits (may be empty for already-formatted)
	_ = edits
}

// Test message handling and routing.
func TestServerHandleMessage(t *testing.T) {
	tests := []struct {
		name           string
		msg            *protocol.Message
		expectResponse bool
		expectShutdown bool
	}{
		{
			name: "initialize request",
			msg: &protocol.Message{
				JSONRPC: "2.0",
				ID:      1,
				Method:  protocol.MethodInitialize,
				Params:  []byte(`{"capabilities":{}}`),
			},
			expectResponse: true,
		},
		{
			name: "initialized notification",
			msg: &protocol.Message{
				JSONRPC: "2.0",
				Method:  protocol.MethodInitialized,
			},
			expectResponse: false,
		},
		{
			name: "shutdown request",
			msg: &protocol.Message{
				JSONRPC: "2.0",
				ID:      2,
				Method:  protocol.MethodShutdown,
			},
			expectResponse: true,
			expectShutdown: true,
		},
		{
			name: "unknown method returns error",
			msg: &protocol.Message{
				JSONRPC: "2.0",
				ID:      3,
				Method:  "unknown/method",
			},
			expectResponse: true, // Returns method not found error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fresh server for each test to avoid state pollution
			server := NewServer()

			response := server.handleMessage(tt.msg)

			if tt.expectResponse {
				assert.NotNil(t, response, "expected response but got nil")
			} else {
				assert.Nil(t, response, "expected no response")
			}
			// Note: shutdown state is internal, verified by Run() loop termination
		})
	}
}

func TestServerHandleInitialize(t *testing.T) {
	server := NewServer()

	msg := &protocol.Message{
		JSONRPC: "2.0",
		ID:      1,
		Method:  protocol.MethodInitialize,
		Params:  []byte(`{"capabilities":{"textDocument":{"completion":{"completionItem":{"snippetSupport":true}}}}}`),
	}

	response := server.handleMessage(msg)

	require.NotNil(t, response, "expected response")
	assert.Equal(t, 1, response.ID, "expected ID 1")
	assert.Nil(t, response.Error, "unexpected error")
	assert.NotNil(t, response.Result, "expected result")
}

func TestServerHandleDidOpen(t *testing.T) {
	server := NewServer()

	content := `- rule: Test
  desc: Test rule
  condition: evt.type = open
  output: "test"
  priority: INFO
`
	params := protocol.DidOpenTextDocumentParams{
		TextDocument: protocol.TextDocumentItem{
			URI:        "file:///test.yaml",
			LanguageID: "falco-yaml",
			Version:    1,
			Text:       content,
		},
	}
	paramsBytes, _ := json.Marshal(params)

	msg := &protocol.Message{
		JSONRPC: "2.0",
		Method:  protocol.MethodTextDocumentDidOpen,
		Params:  paramsBytes,
	}

	response := server.handleMessage(msg)

	// didOpen is a notification, no response expected
	assert.Nil(t, response, "expected no response for notification")

	// Document should be stored
	doc, ok := server.Documents().Get("file:///test.yaml")
	assert.True(t, ok, "document should be stored after didOpen")
	assert.Equal(t, 1, doc.Version, "expected version 1")
}

func TestServerHandleDidChange(t *testing.T) {
	server := NewServer()

	// First open a document
	openParams := protocol.DidOpenTextDocumentParams{
		TextDocument: protocol.TextDocumentItem{
			URI:     "file:///test.yaml",
			Version: 1,
			Text:    testBasicRuleContent,
		},
	}
	openBytes, _ := json.Marshal(openParams)
	server.handleMessage(&protocol.Message{
		JSONRPC: "2.0",
		Method:  protocol.MethodTextDocumentDidOpen,
		Params:  openBytes,
	})

	// Now change it
	newContent := `- rule: Updated
  desc: Updated
  condition: evt.type = close
  output: "updated"
  priority: WARNING
`
	changeParams := protocol.DidChangeTextDocumentParams{
		TextDocument: protocol.VersionedTextDocumentIdentifier{
			URI:     "file:///test.yaml",
			Version: 2,
		},
		ContentChanges: []protocol.TextDocumentContentChangeEvent{
			{Text: newContent},
		},
	}
	changeBytes, _ := json.Marshal(changeParams)

	msg := &protocol.Message{
		JSONRPC: "2.0",
		Method:  protocol.MethodTextDocumentDidChange,
		Params:  changeBytes,
	}

	response := server.handleMessage(msg)

	// didChange is a notification, no response expected
	assert.Nil(t, response, "expected no response for notification")

	// Document should be updated
	doc, ok := server.Documents().Get("file:///test.yaml")
	assert.True(t, ok, "document should exist after didChange")
	assert.Equal(t, 2, doc.Version, "expected version 2")
	assert.Equal(t, newContent, doc.Content, "content should be updated")
}

func TestServerHandleDidClose(t *testing.T) {
	server := NewServer()

	// First open a document
	openParams := protocol.DidOpenTextDocumentParams{
		TextDocument: protocol.TextDocumentItem{
			URI:     "file:///test.yaml",
			Version: 1,
			Text:    "- rule: Test\n",
		},
	}
	openBytes, _ := json.Marshal(openParams)
	server.handleMessage(&protocol.Message{
		JSONRPC: "2.0",
		Method:  protocol.MethodTextDocumentDidOpen,
		Params:  openBytes,
	})

	// Verify it exists
	_, ok := server.Documents().Get("file:///test.yaml")
	require.True(t, ok, "document should exist after open")

	// Now close it
	closeParams := protocol.DidCloseTextDocumentParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.yaml"},
	}
	closeBytes, _ := json.Marshal(closeParams)

	msg := &protocol.Message{
		JSONRPC: "2.0",
		Method:  protocol.MethodTextDocumentDidClose,
		Params:  closeBytes,
	}

	response := server.handleMessage(msg)

	// didClose is a notification, no response expected
	assert.Nil(t, response, "expected no response for notification")

	// Document should be removed
	_, ok = server.Documents().Get("file:///test.yaml")
	assert.False(t, ok, "document should be removed after didClose")
}

func TestServerConcurrentAccess(t *testing.T) {
	server := NewServer()
	var wg sync.WaitGroup

	// Simulate concurrent document operations
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			uri := fmt.Sprintf("file:///test%d.yaml", id)
			content := fmt.Sprintf("- rule: Test%d\n  desc: Test\n  condition: evt.type = open\n  output: \"test\"\n  priority: INFO\n", id)

			// Open document
			openParams := protocol.DidOpenTextDocumentParams{
				TextDocument: protocol.TextDocumentItem{
					URI:     uri,
					Version: 1,
					Text:    content,
				},
			}
			openBytes, _ := json.Marshal(openParams)
			server.handleMessage(&protocol.Message{
				JSONRPC: "2.0",
				Method:  protocol.MethodTextDocumentDidOpen,
				Params:  openBytes,
			})

			// Check document exists
			_, ok := server.Documents().Get(uri)
			assert.True(t, ok, "document %s should exist", uri)
		}(i)
	}

	wg.Wait()

	// All documents should exist
	assert.Equal(t, 10, server.Documents().Count(), "expected 10 documents")
}

func TestServerHandleCompletion(t *testing.T) {
	server := NewServer()

	// First open a document
	content := `- rule: Test
  desc: Test
  condition: evt.
  output: "test"
  priority: INFO
`
	openParams := protocol.DidOpenTextDocumentParams{
		TextDocument: protocol.TextDocumentItem{
			URI:     "file:///test.yaml",
			Version: 1,
			Text:    content,
		},
	}
	openBytes, _ := json.Marshal(openParams)
	server.handleMessage(&protocol.Message{
		JSONRPC: "2.0",
		Method:  protocol.MethodTextDocumentDidOpen,
		Params:  openBytes,
	})

	// Request completion
	completionParams := protocol.CompletionParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.yaml"},
			Position:     protocol.Position{Line: 2, Character: 16},
		},
	}
	completionBytes, _ := json.Marshal(completionParams)

	msg := &protocol.Message{
		JSONRPC: "2.0",
		ID:      1,
		Method:  protocol.MethodTextDocumentCompletion,
		Params:  completionBytes,
	}

	response := server.handleMessage(msg)
	require.NotNil(t, response, "expected response for completion request")
	assert.Nil(t, response.Error, "unexpected error")
}

func TestServerHandleHover(t *testing.T) {
	server := NewServer()
	openDocumentForTest(server, testBasicRuleContent)

	// Request hover
	hoverParams := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.yaml"},
		Position:     protocol.Position{Line: 2, Character: 14},
	}
	hoverBytes, _ := json.Marshal(hoverParams)

	msg := &protocol.Message{
		JSONRPC: "2.0",
		ID:      1,
		Method:  protocol.MethodTextDocumentHover,
		Params:  hoverBytes,
	}

	response := server.handleMessage(msg)
	require.NotNil(t, response, "expected response for hover request")
	assert.Nil(t, response.Error, "unexpected error")
}

func TestServerHandleDefinition(t *testing.T) {
	server := NewServer()

	// Use testMacroRuleContent which has a macro and rule referencing it
	openDocumentForTest(server, testMacroRuleContent)

	// Request definition for the macro reference (line 5, is_shell)
	defParams := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.yaml"},
		Position:     protocol.Position{Line: 5, Character: 14},
	}
	defBytes, _ := json.Marshal(defParams)

	msg := &protocol.Message{
		JSONRPC: "2.0",
		ID:      1,
		Method:  protocol.MethodTextDocumentDefinition,
		Params:  defBytes,
	}

	response := server.handleMessage(msg)
	require.NotNil(t, response, "expected response for definition request")
	assert.Nil(t, response.Error, "unexpected error")
}

func TestServerHandleDocumentSymbol(t *testing.T) {
	server := NewServer()
	openDocumentForTest(server, testBasicRuleContent)

	// Request document symbols
	symbolParams := protocol.DocumentSymbolParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.yaml"},
	}
	symbolBytes, _ := json.Marshal(symbolParams)

	msg := &protocol.Message{
		JSONRPC: "2.0",
		ID:      1,
		Method:  protocol.MethodTextDocumentDocumentSymbol,
		Params:  symbolBytes,
	}

	response := server.handleMessage(msg)
	require.NotNil(t, response, "expected response for document symbol request")
	assert.Nil(t, response.Error, "unexpected error")
}

func TestServerHandleFormatting(t *testing.T) {
	server := NewServer()
	openDocumentForTest(server, testBasicRuleContent)

	// Request formatting
	formatParams := protocol.DocumentFormattingParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.yaml"},
		Options: protocol.FormattingOptions{
			TabSize:      2,
			InsertSpaces: true,
		},
	}
	formatBytes, _ := json.Marshal(formatParams)

	msg := &protocol.Message{
		JSONRPC: "2.0",
		ID:      1,
		Method:  protocol.MethodTextDocumentFormatting,
		Params:  formatBytes,
	}

	response := server.handleMessage(msg)
	require.NotNil(t, response, "expected response for formatting request")
	assert.Nil(t, response.Error, "unexpected error")
}

func TestServerHandleReferences(t *testing.T) {
	server := NewServer()

	// Use testMacroRuleContent which has a macro and rule referencing it
	openDocumentForTest(server, testMacroRuleContent)

	// Request references
	refParams := protocol.ReferenceParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.yaml"},
			Position:     protocol.Position{Line: 0, Character: 10},
		},
		Context: protocol.ReferenceContext{IncludeDeclaration: true},
	}
	refBytes, _ := json.Marshal(refParams)

	msg := &protocol.Message{
		JSONRPC: "2.0",
		ID:      1,
		Method:  protocol.MethodTextDocumentReferences,
		Params:  refBytes,
	}

	response := server.handleMessage(msg)
	require.NotNil(t, response, "expected response for references request")
	assert.Nil(t, response.Error, "unexpected error")
}

func TestInitLogger(t *testing.T) {
	// Test with empty log file (should use stderr)
	err := InitLogger("", 0)
	assert.NoError(t, err, "InitLogger with empty file should not error")
}

func TestServerPublishDiagnostics(_ *testing.T) {
	// Create a server with a mock transport to capture output
	server := NewServer()

	// Test publishDiagnostics with version
	version := 1
	diags := []protocol.Diagnostic{
		{
			Range: protocol.Range{
				Start: protocol.Position{Line: 0, Character: 0},
				End:   protocol.Position{Line: 0, Character: 10},
			},
			Severity: protocol.DiagnosticSeverityError,
			Message:  "Test error",
		},
	}

	// This will fail to write (no real transport), but should not panic
	server.publishDiagnostics("file:///test.yaml", &version, diags)

	// Test without version
	server.publishDiagnostics("file:///test.yaml", nil, diags)
}

func TestServerHandleMessageExit(t *testing.T) {
	// We can't actually test exit because it calls os.Exit
	// But we can verify the method exists and the code path is correct
	server := NewServer()

	// Test that handleMessage returns nil for exit (before os.Exit is called)
	// Note: We can't actually call this because os.Exit will terminate the test
	// This is just to document the expected behavior
	_ = server

	// Instead, test other message handling paths
	msg := &protocol.Message{
		JSONRPC: "2.0",
		ID:      1,
		Method:  protocol.MethodInitialize,
		Params:  []byte(`{}`),
	}
	response := server.handleMessage(msg)
	assert.NotNil(t, response, "expected response for initialize")
}

func TestServerHandleUnknownMethod(t *testing.T) {
	server := NewServer()

	msg := &protocol.Message{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "unknown/method",
	}

	response := server.handleMessage(msg)
	require.NotNil(t, response, "expected response for unknown method")
	assert.NotNil(t, response.Error, "expected error for unknown method")
}

func TestServerHandleNotification(t *testing.T) {
	server := NewServer()

	// Test initialized notification (no ID = notification)
	msg := &protocol.Message{
		JSONRPC: "2.0",
		Method:  protocol.MethodInitialized,
	}

	response := server.handleMessage(msg)
	assert.Nil(t, response, "notifications should not return a response")
}

func TestServerProviderAccessors(t *testing.T) {
	server := NewServer()

	// Test all provider accessors
	assert.NotNil(t, server.Documents(), "Documents() should not be nil")
	assert.NotNil(t, server.Completion(), "Completion() should not be nil")
	assert.NotNil(t, server.Hover(), "Hover() should not be nil")
	assert.NotNil(t, server.Definition(), "Definition() should not be nil")
	assert.NotNil(t, server.Symbols(), "Symbols() should not be nil")
	assert.NotNil(t, server.References(), "References() should not be nil")
	assert.NotNil(t, server.Formatting(), "Formatting() should not be nil")
}

func TestServerRunWithContext_ContextCanceled(t *testing.T) {
	// Create a pipe for mock I/O
	reader, writer := io.Pipe()
	var output bytes.Buffer

	// Create server with mock transport
	tr := transport.New(reader, &output)
	server := NewServerWithTransport(tr)

	// Create a context that we'll cancel
	ctx, cancel := context.WithCancel(context.Background())

	// Run server in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.RunWithContext(ctx)
	}()

	// Give the server time to start
	time.Sleep(10 * time.Millisecond)

	// Cancel the context
	cancel()

	// Close the writer to unblock any pending reads
	_ = writer.Close()

	// Wait for server to exit
	select {
	case err := <-errChan:
		// Context canceled error is expected
		assert.True(t, errors.Is(err, context.Canceled) || err == nil, "expected context.Canceled or nil, got %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("server did not exit after context cancellation")
	}

	_ = reader.Close()
}

func TestServerRunWithContext_EOF(t *testing.T) {
	// Create a pipe for mock I/O
	reader, writer := io.Pipe()
	var output bytes.Buffer

	// Create server with mock transport
	tr := transport.New(reader, &output)
	server := NewServerWithTransport(tr)

	// Run server in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.RunWithContext(context.Background())
	}()

	// Give the server time to start
	time.Sleep(10 * time.Millisecond)

	// Close the writer to send EOF
	_ = writer.Close()

	// Wait for server to exit
	select {
	case err := <-errChan:
		// EOF should result in nil error (clean shutdown)
		assert.NoError(t, err, "expected nil error on EOF")
	case <-time.After(2 * time.Second):
		t.Fatal("server did not exit after EOF")
	}

	_ = reader.Close()
}

func TestServerRunWithContext_ShutdownRequest(t *testing.T) {
	// Create a pipe for mock I/O
	reader, writer := io.Pipe()
	var output bytes.Buffer

	// Create server with mock transport
	tr := transport.New(reader, &output)
	server := NewServerWithTransport(tr)

	// Run server in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.RunWithContext(context.Background())
	}()

	// Give the server time to start
	time.Sleep(10 * time.Millisecond)

	// Send shutdown request
	shutdownMsg := `{"jsonrpc":"2.0","id":1,"method":"shutdown"}`
	header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(shutdownMsg))
	_, err := writer.Write([]byte(header + shutdownMsg))
	require.NoError(t, err, "failed to write shutdown message")

	// Give server time to process
	time.Sleep(50 * time.Millisecond)

	// Close the writer
	_ = writer.Close()

	// Wait for server to exit
	select {
	case err := <-errChan:
		// Should exit cleanly after shutdown
		assert.NoError(t, err, "expected nil error after shutdown")
	case <-time.After(2 * time.Second):
		t.Fatal("server did not exit after shutdown")
	}

	_ = reader.Close()
}

func TestServerRun(t *testing.T) {
	// Create a pipe for mock I/O
	reader, writer := io.Pipe()
	var output bytes.Buffer

	// Create server with mock transport
	tr := transport.New(reader, &output)
	server := NewServerWithTransport(tr)

	// Run server in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Run()
	}()

	// Give the server time to start
	time.Sleep(10 * time.Millisecond)

	// Close the writer to send EOF
	_ = writer.Close()

	// Wait for server to exit
	select {
	case err := <-errChan:
		// EOF should result in nil error
		assert.NoError(t, err, "expected nil error on EOF")
	case <-time.After(2 * time.Second):
		t.Fatal("server did not exit after EOF")
	}

	_ = reader.Close()
}

func TestNewServerWithTransport(t *testing.T) {
	// Create a mock transport
	reader := strings.NewReader("")
	var output bytes.Buffer
	tr := transport.New(reader, &output)

	// Create server with custom transport
	server := NewServerWithTransport(tr)

	require.NotNil(t, server, "NewServerWithTransport returned nil")
	assert.NotNil(t, server.Documents(), "documents should not be nil")
	assert.NotNil(t, server.Completion(), "completion should not be nil")
}
