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

// Package hover provides hover information functionality.
package hover

import (
	"testing"

	"github.com/c2ndev/falco-lsp/internal/analyzer"
	"github.com/c2ndev/falco-lsp/internal/lsp/document"
	"github.com/c2ndev/falco-lsp/internal/lsp/protocol"
	"github.com/c2ndev/falco-lsp/internal/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestProvider() (*Provider, *document.Store) {
	docs := document.NewStore()
	return New(docs), docs
}

// analyzeDocument parses and analyzes a document, populating its Symbols field.
func analyzeDocument(doc *document.Document) {
	if doc.Result == nil {
		return
	}
	a := analyzer.NewAnalyzer()
	result := a.Analyze(doc.Result.Document, doc.URI)
	doc.Symbols = result.Symbols
}

func TestNewProvider(t *testing.T) {
	hp, _ := newTestProvider()

	require.NotNil(t, hp, "New returned nil")
}

func TestGetHover(_ *testing.T) {
	hp, docs := newTestProvider()

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
	_ = docs.Set(doc)

	params := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "test.yaml"},
		Position:     protocol.Position{Line: 2, Character: 14}, // On "evt.type"
	}

	hover := hp.GetHover(doc, params)
	// May return nil if no hover info
	_ = hover
}

func TestGetHover_NilDoc(t *testing.T) {
	hp, _ := newTestProvider()

	params := protocol.TextDocumentPositionParams{}
	hover := hp.GetHover(nil, params)

	assert.Nil(t, hover, "expected nil for nil document")
}

func TestHoverOnMacro(_ *testing.T) {
	hp, docs := newTestProvider()

	content := `- macro: is_shell
  condition: proc.name in (bash, sh)

- rule: Shell Spawn
  desc: Test
  condition: is_shell
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
	_ = docs.Set(doc)

	// Analyze to register the macro
	analyzeDocument(doc)

	params := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "test.yaml"},
		Position:     protocol.Position{Line: 5, Character: 14}, // On "is_shell"
	}

	hover := hp.GetHover(doc, params)
	// Should return macro info
	_ = hover
}

func TestHoverOnList(_ *testing.T) {
	hp, docs := newTestProvider()

	content := `- list: shell_binaries
  items: [bash, sh, zsh]

- rule: Shell Spawn
  desc: Test
  condition: proc.name in (shell_binaries)
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
	_ = docs.Set(doc)

	analyzeDocument(doc)

	params := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "test.yaml"},
		Position:     protocol.Position{Line: 5, Character: 30}, // On "shell_binaries"
	}

	hover := hp.GetHover(doc, params)
	_ = hover
}

func TestHoverOnKeyword(_ *testing.T) {
	hp, docs := newTestProvider()

	content := `- rule: Test
  desc: Test
  condition: evt.type = open and proc.name = bash
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
	_ = docs.Set(doc)

	params := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "test.yaml"},
		Position:     protocol.Position{Line: 2, Character: 28}, // On "and"
	}

	hover := hp.GetHover(doc, params)
	// May return operator info
	_ = hover
}

func TestHoverOutOfBounds(_ *testing.T) {
	hp, docs := newTestProvider()

	content := `- rule: Test
`
	result, _ := parser.Parse(content, "test.yaml")
	doc := &document.Document{
		URI:     "test.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}
	_ = docs.Set(doc)

	params := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "test.yaml"},
		Position:     protocol.Position{Line: 100, Character: 0}, // Out of bounds
	}

	hover := hp.GetHover(doc, params)
	// Should handle gracefully
	_ = hover
}
