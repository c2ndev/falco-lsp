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

package handlers

import (
	"encoding/json"
	"testing"

	"github.com/c2ndev/falco-lsp/internal/lsp/document"
	"github.com/c2ndev/falco-lsp/internal/lsp/protocol"
	"github.com/c2ndev/falco-lsp/internal/lsp/router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestHandlers() *Handlers {
	docs := document.NewStore()
	return New(Config{
		Documents: docs,
		PublishDiagFn: func(_ string, _ *int, _ []protocol.Diagnostic) {
			// No-op for tests
		},
	})
}

func TestHandlers_Initialize(t *testing.T) {
	h := newTestHandlers()

	msg := &protocol.Message{
		JSONRPC: "2.0",
		ID:      1,
		Method:  protocol.MethodInitialize,
		Params:  []byte(`{"capabilities":{}}`),
	}

	response := h.HandleInitialize(msg)

	require.NotNil(t, response, "expected response")
	assert.Equal(t, 1, response.ID, "expected ID 1")
	assert.Nil(t, response.Error, "unexpected error")
}

func TestHandlers_DidOpen(t *testing.T) {
	h := newTestHandlers()

	params := protocol.DidOpenTextDocumentParams{
		TextDocument: protocol.TextDocumentItem{
			URI:     "file:///test.yaml",
			Version: 1,
			Text:    "- rule: Test\n  desc: test\n",
		},
	}
	paramsBytes, _ := json.Marshal(params)

	msg := &protocol.Message{
		JSONRPC: "2.0",
		Method:  protocol.MethodTextDocumentDidOpen,
		Params:  paramsBytes,
	}

	h.HandleDidOpen(msg)

	doc, ok := h.documents.Get("file:///test.yaml")
	assert.True(t, ok, "document should exist after didOpen")
	assert.Equal(t, 1, doc.Version, "expected version 1")
}

func TestHandlers_DidChange(t *testing.T) {
	h := newTestHandlers()

	// First open
	openParams := protocol.DidOpenTextDocumentParams{
		TextDocument: protocol.TextDocumentItem{
			URI:     "file:///test.yaml",
			Version: 1,
			Text:    "- rule: Test\n",
		},
	}
	openBytes, _ := json.Marshal(openParams)
	h.HandleDidOpen(&protocol.Message{Params: openBytes})

	// Then change
	changeParams := protocol.DidChangeTextDocumentParams{
		TextDocument: protocol.VersionedTextDocumentIdentifier{
			URI:     "file:///test.yaml",
			Version: 2,
		},
		ContentChanges: []protocol.TextDocumentContentChangeEvent{
			{Text: "- rule: Updated\n"},
		},
	}
	changeBytes, _ := json.Marshal(changeParams)

	h.HandleDidChange(&protocol.Message{Params: changeBytes})

	doc, _ := h.documents.Get("file:///test.yaml")
	assert.Equal(t, 2, doc.Version, "expected version 2")
	assert.Equal(t, "- rule: Updated\n", doc.Content, "content not updated")
}

func TestHandlers_DidClose(t *testing.T) {
	h := newTestHandlers()

	// Open
	openParams := protocol.DidOpenTextDocumentParams{
		TextDocument: protocol.TextDocumentItem{
			URI:     "file:///test.yaml",
			Version: 1,
			Text:    "- rule: Test\n",
		},
	}
	openBytes, _ := json.Marshal(openParams)
	h.HandleDidOpen(&protocol.Message{Params: openBytes})

	// Close
	closeParams := protocol.DidCloseTextDocumentParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.yaml"},
	}
	closeBytes, _ := json.Marshal(closeParams)

	h.HandleDidClose(&protocol.Message{Params: closeBytes})

	_, ok := h.documents.Get("file:///test.yaml")
	assert.False(t, ok, "document should be removed after didClose")
}

func TestHandlers_Register(t *testing.T) {
	h := newTestHandlers()
	r := router.New()

	h.Register(r)

	// Check key methods are registered
	methods := []protocol.Method{
		protocol.MethodInitialize,
		protocol.MethodShutdown,
		protocol.MethodTextDocumentDidOpen,
		protocol.MethodTextDocumentCompletion,
		protocol.MethodTextDocumentHover,
		protocol.MethodTextDocumentDefinition,
	}

	for _, m := range methods {
		assert.True(t, r.HasHandler(m), "handler for %s should be registered", m)
	}
}

func TestHandlers_Callbacks(t *testing.T) {
	initCalled := false
	shutdownCalled := false

	h := New(Config{
		Documents: document.NewStore(),
		OnInitialized: func() {
			initCalled = true
		},
		OnShutdown: func() {
			shutdownCalled = true
		},
	})

	h.HandleInitialized(&protocol.Message{})
	assert.True(t, initCalled, "onInitialized callback should have been called")

	h.HandleShutdown(&protocol.Message{ID: 1})
	assert.True(t, shutdownCalled, "onShutdown callback should have been called")
}

func TestHandlers_HandleCompletion(t *testing.T) {
	h := newTestHandlers()

	// First open a document
	openParams := protocol.DidOpenTextDocumentParams{
		TextDocument: protocol.TextDocumentItem{
			URI:     "file:///test.yaml",
			Version: 1,
			Text:    "- rule: Test\n  condition: evt.\n",
		},
	}
	openBytes, _ := json.Marshal(openParams)
	h.HandleDidOpen(&protocol.Message{Params: openBytes})

	// Request completion
	compParams := protocol.CompletionParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.yaml"},
			Position:     protocol.Position{Line: 1, Character: 16},
		},
	}
	compBytes, _ := json.Marshal(compParams)

	response := h.HandleCompletion(&protocol.Message{ID: 1, Params: compBytes})

	require.NotNil(t, response, "expected response")
	assert.Nil(t, response.Error, "unexpected error")
}

func TestHandlers_HandleCompletion_InvalidParams(t *testing.T) {
	h := newTestHandlers()

	response := h.HandleCompletion(&protocol.Message{ID: 1, Params: []byte(`invalid`)})

	require.NotNil(t, response, "expected response")
	assert.NotNil(t, response.Error, "expected error for invalid params")
}

func TestHandlers_HandleHover(t *testing.T) {
	h := newTestHandlers()

	// Open document
	openParams := protocol.DidOpenTextDocumentParams{
		TextDocument: protocol.TextDocumentItem{
			URI:     "file:///test.yaml",
			Version: 1,
			Text:    "- rule: Test\n  condition: evt.type\n",
		},
	}
	openBytes, _ := json.Marshal(openParams)
	h.HandleDidOpen(&protocol.Message{Params: openBytes})

	// Request hover
	hoverParams := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.yaml"},
		Position:     protocol.Position{Line: 1, Character: 14},
	}
	hoverBytes, _ := json.Marshal(hoverParams)

	response := h.HandleHover(&protocol.Message{ID: 1, Params: hoverBytes})

	require.NotNil(t, response, "expected response")
	assert.Nil(t, response.Error, "unexpected error")
}

func TestHandlers_HandleHover_InvalidParams(t *testing.T) {
	h := newTestHandlers()

	response := h.HandleHover(&protocol.Message{ID: 1, Params: []byte(`invalid`)})

	require.NotNil(t, response, "expected response")
	assert.NotNil(t, response.Error, "expected error for invalid params")
}

func TestHandlers_HandleDefinition(t *testing.T) {
	h := newTestHandlers()

	// Open document with macro definition and usage
	openParams := protocol.DidOpenTextDocumentParams{
		TextDocument: protocol.TextDocumentItem{
			URI:     "file:///test.yaml",
			Version: 1,
			Text: `- macro: my_macro
  condition: evt.type = open
- rule: Test
  condition: my_macro
`,
		},
	}
	openBytes, _ := json.Marshal(openParams)
	h.HandleDidOpen(&protocol.Message{Params: openBytes})

	// Request definition
	defParams := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.yaml"},
		Position:     protocol.Position{Line: 3, Character: 14},
	}
	defBytes, _ := json.Marshal(defParams)

	response := h.HandleDefinition(&protocol.Message{ID: 1, Params: defBytes})

	require.NotNil(t, response, "expected response")
	assert.Nil(t, response.Error, "unexpected error")
}

func TestHandlers_HandleDefinition_InvalidParams(t *testing.T) {
	h := newTestHandlers()

	response := h.HandleDefinition(&protocol.Message{ID: 1, Params: []byte(`invalid`)})

	require.NotNil(t, response, "expected response")
	assert.NotNil(t, response.Error, "expected error for invalid params")
}

func TestHandlers_HandleReferences(t *testing.T) {
	h := newTestHandlers()

	// Open document
	openParams := protocol.DidOpenTextDocumentParams{
		TextDocument: protocol.TextDocumentItem{
			URI:     "file:///test.yaml",
			Version: 1,
			Text: `- macro: my_macro
  condition: evt.type = open
- rule: Test
  condition: my_macro
`,
		},
	}
	openBytes, _ := json.Marshal(openParams)
	h.HandleDidOpen(&protocol.Message{Params: openBytes})

	// Request references
	refParams := protocol.ReferenceParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.yaml"},
			Position:     protocol.Position{Line: 0, Character: 10},
		},
		Context: protocol.ReferenceContext{IncludeDeclaration: true},
	}
	refBytes, _ := json.Marshal(refParams)

	response := h.HandleReferences(&protocol.Message{ID: 1, Params: refBytes})

	require.NotNil(t, response, "expected response")
	assert.Nil(t, response.Error, "unexpected error")
}

func TestHandlers_HandleReferences_InvalidParams(t *testing.T) {
	h := newTestHandlers()

	response := h.HandleReferences(&protocol.Message{ID: 1, Params: []byte(`invalid`)})

	require.NotNil(t, response, "expected response")
	assert.NotNil(t, response.Error, "expected error for invalid params")
}

func TestHandlers_HandleDocumentSymbol(t *testing.T) {
	h := newTestHandlers()

	// Open document
	openParams := protocol.DidOpenTextDocumentParams{
		TextDocument: protocol.TextDocumentItem{
			URI:     "file:///test.yaml",
			Version: 1,
			Text: `- macro: my_macro
  condition: evt.type = open
- rule: Test Rule
  condition: my_macro
`,
		},
	}
	openBytes, _ := json.Marshal(openParams)
	h.HandleDidOpen(&protocol.Message{Params: openBytes})

	// Request symbols
	symParams := protocol.DocumentSymbolParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.yaml"},
	}
	symBytes, _ := json.Marshal(symParams)

	response := h.HandleDocumentSymbol(&protocol.Message{ID: 1, Params: symBytes})

	require.NotNil(t, response, "expected response")
	assert.Nil(t, response.Error, "unexpected error")
}

func TestHandlers_HandleDocumentSymbol_InvalidParams(t *testing.T) {
	h := newTestHandlers()

	response := h.HandleDocumentSymbol(&protocol.Message{ID: 1, Params: []byte(`invalid`)})

	require.NotNil(t, response, "expected response")
	assert.NotNil(t, response.Error, "expected error for invalid params")
}

func TestHandlers_HandleFormatting(t *testing.T) {
	h := newTestHandlers()

	// Open document with poor formatting
	openParams := protocol.DidOpenTextDocumentParams{
		TextDocument: protocol.TextDocumentItem{
			URI:     "file:///test.yaml",
			Version: 1,
			Text:    "- rule:   Test\n  condition:    evt.type=open\n",
		},
	}
	openBytes, _ := json.Marshal(openParams)
	h.HandleDidOpen(&protocol.Message{Params: openBytes})

	// Request formatting
	fmtParams := protocol.DocumentFormattingParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.yaml"},
		Options: protocol.FormattingOptions{
			TabSize:      2,
			InsertSpaces: true,
		},
	}
	fmtBytes, _ := json.Marshal(fmtParams)

	response := h.HandleFormatting(&protocol.Message{ID: 1, Params: fmtBytes})

	require.NotNil(t, response, "expected response")
	assert.Nil(t, response.Error, "unexpected error")
}

func TestHandlers_HandleFormatting_InvalidParams(t *testing.T) {
	h := newTestHandlers()

	response := h.HandleFormatting(&protocol.Message{ID: 1, Params: []byte(`invalid`)})

	require.NotNil(t, response, "expected response")
	assert.NotNil(t, response.Error, "expected error for invalid params")
}

func TestHandlers_HandleRangeFormatting(t *testing.T) {
	h := newTestHandlers()

	// Open document
	openParams := protocol.DidOpenTextDocumentParams{
		TextDocument: protocol.TextDocumentItem{
			URI:     "file:///test.yaml",
			Version: 1,
			Text:    "- rule:   Test\n  condition:    evt.type=open\n",
		},
	}
	openBytes, _ := json.Marshal(openParams)
	h.HandleDidOpen(&protocol.Message{Params: openBytes})

	// Request range formatting
	fmtParams := protocol.DocumentRangeFormattingParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.yaml"},
		Range: protocol.Range{
			Start: protocol.Position{Line: 0, Character: 0},
			End:   protocol.Position{Line: 1, Character: 0},
		},
		Options: protocol.FormattingOptions{
			TabSize:      2,
			InsertSpaces: true,
		},
	}
	fmtBytes, _ := json.Marshal(fmtParams)

	response := h.HandleRangeFormatting(&protocol.Message{ID: 1, Params: fmtBytes})

	require.NotNil(t, response, "expected response")
	assert.Nil(t, response.Error, "unexpected error")
}

func TestHandlers_HandleRangeFormatting_InvalidParams(t *testing.T) {
	h := newTestHandlers()

	response := h.HandleRangeFormatting(&protocol.Message{ID: 1, Params: []byte(`invalid`)})

	require.NotNil(t, response, "expected response")
	assert.NotNil(t, response.Error, "expected error for invalid params")
}

func TestHandlers_HandleDidSave(_ *testing.T) {
	h := newTestHandlers()

	// Open document
	openParams := protocol.DidOpenTextDocumentParams{
		TextDocument: protocol.TextDocumentItem{
			URI:     "file:///test.yaml",
			Version: 1,
			Text:    "- rule: Test\n",
		},
	}
	openBytes, _ := json.Marshal(openParams)
	h.HandleDidOpen(&protocol.Message{Params: openBytes})

	// Save document
	saveParams := protocol.DidSaveTextDocumentParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.yaml"},
	}
	saveBytes, _ := json.Marshal(saveParams)

	h.HandleDidSave(&protocol.Message{Params: saveBytes})
	// No error means success for notification
}

func TestHandlers_HandleDidSave_InvalidParams(_ *testing.T) {
	h := newTestHandlers()

	// Should not panic on invalid params
	h.HandleDidSave(&protocol.Message{Params: []byte(`invalid`)})
}

func TestHandlers_DocumentNotFound(t *testing.T) {
	h := newTestHandlers()

	// Request completion for non-existent document
	compParams := protocol.CompletionParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: "file:///nonexistent.yaml"},
			Position:     protocol.Position{Line: 0, Character: 0},
		},
	}
	compBytes, _ := json.Marshal(compParams)

	response := h.HandleCompletion(&protocol.Message{ID: 1, Params: compBytes})

	require.NotNil(t, response, "expected response")
	// Should return empty result, not error
	assert.Nil(t, response.Error, "unexpected error for non-existent document")
}
