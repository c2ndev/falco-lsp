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

// Package hover provides hover information functionality.
package hover

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falco-lsp/internal/analyzer"
	"github.com/falcosecurity/falco-lsp/internal/lsp/document"
	"github.com/falcosecurity/falco-lsp/internal/lsp/protocol"
	"github.com/falcosecurity/falco-lsp/internal/parser"
)

func newTestProvider() (*Provider, *document.Store) {
	docs := document.NewStore()
	return New(docs), docs
}

func analyzeDocument(doc *document.Document) {
	if doc.Result == nil {
		return
	}
	a := analyzer.NewAnalyzer()
	result := a.Analyze(doc.Result.Document, doc.URI)
	doc.Symbols = result.Symbols
}

func TestNewProvider(t *testing.T) {
	t.Parallel()
	hp, _ := newTestProvider()
	require.NotNil(t, hp, "New returned nil")
}

func TestGetHover_NilDoc(t *testing.T) {
	t.Parallel()
	hp, _ := newTestProvider()

	params := protocol.TextDocumentPositionParams{}
	hover := hp.GetHover(nil, params)

	assert.Nil(t, hover, "expected nil for nil document")
}

func TestGetHover_FalcoField(t *testing.T) {
	t.Parallel()
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
	analyzeDocument(doc)

	params := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "test.yaml"},
		Position:     protocol.Position{Line: 2, Character: 14}, // On "evt.type"
	}

	hover := hp.GetHover(doc, params)
	require.NotNil(t, hover, "Should return hover info for evt.type field")
	assert.Equal(t, protocol.MarkupKindMarkdown, hover.Contents.Kind, "Should be markdown")
	assert.Contains(t, hover.Contents.Value, "evt.type", "Should contain field name")
}

func TestGetHover_ProcNameField(t *testing.T) {
	t.Parallel()
	hp, docs := newTestProvider()

	content := `- rule: Test Rule
  desc: Test
  condition: proc.name = bash
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
	analyzeDocument(doc)

	params := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "test.yaml"},
		Position:     protocol.Position{Line: 2, Character: 14}, // On "proc.name"
	}

	hover := hp.GetHover(doc, params)
	require.NotNil(t, hover, "Should return hover for proc.name")
	assert.Contains(t, hover.Contents.Value, "proc.name", "Should contain field name")
}

func TestGetHover_Macro(t *testing.T) {
	t.Parallel()
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
	analyzeDocument(doc)

	params := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "test.yaml"},
		Position:     protocol.Position{Line: 5, Character: 14}, // On "is_shell"
	}

	hover := hp.GetHover(doc, params)
	require.NotNil(t, hover, "Should return hover for macro reference")
	assert.Contains(t, hover.Contents.Value, "Macro: is_shell", "Should contain macro name")
	assert.Contains(t, hover.Contents.Value, "proc.name in (bash, sh)", "Should contain macro condition")
}

func TestGetHover_List(t *testing.T) {
	t.Parallel()
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
	require.NotNil(t, hover, "Should return hover for list reference")
	assert.Contains(t, hover.Contents.Value, "List: shell_binaries", "Should contain list name")
	assert.Contains(t, hover.Contents.Value, "bash", "Should contain list items")
}

func TestGetHover_Rule(t *testing.T) {
	t.Parallel()
	hp, docs := newTestProvider()

	content := `- rule: BaseRule
  desc: A base rule
  condition: evt.type = open
  output: "test"
  priority: INFO
  source: syscall

- rule: DerivedRule
  desc: Test
  condition: BaseRule
  output: "derived"
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
		Position:     protocol.Position{Line: 9, Character: 14}, // On "BaseRule"
	}

	hover := hp.GetHover(doc, params)
	require.NotNil(t, hover, "Should return hover for rule reference")
	assert.Contains(t, hover.Contents.Value, "Rule: BaseRule", "Should contain rule name")
}

func TestGetHover_OnKeyword(t *testing.T) {
	t.Parallel()
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
	analyzeDocument(doc)

	params := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "test.yaml"},
		Position:     protocol.Position{Line: 2, Character: 28}, // On "and"
	}

	hover := hp.GetHover(doc, params)
	// "and" is not a field or user-defined symbol, so no hover
	assert.Nil(t, hover, "Should return nil for keyword 'and'")
}

func TestGetHover_OnWhitespace(t *testing.T) {
	t.Parallel()
	hp, docs := newTestProvider()

	content := `- rule: Test
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
	analyzeDocument(doc)

	params := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "test.yaml"},
		Position:     protocol.Position{Line: 1, Character: 0}, // On leading whitespace
	}

	hover := hp.GetHover(doc, params)
	assert.Nil(t, hover, "Should return nil for whitespace position")
}

func TestGetHover_OutOfBounds(t *testing.T) {
	t.Parallel()
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
		Position:     protocol.Position{Line: 100, Character: 0},
	}

	hover := hp.GetHover(doc, params)
	assert.Nil(t, hover, "Should return nil for out of bounds position")
}

func TestGetHover_EmptyDocument(t *testing.T) {
	t.Parallel()
	hp, docs := newTestProvider()

	doc := &document.Document{
		URI:     "test.yaml",
		Content: "",
		Version: 1,
	}
	_ = docs.Set(doc)

	params := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "test.yaml"},
		Position:     protocol.Position{Line: 0, Character: 0},
	}

	hover := hp.GetHover(doc, params)
	assert.Nil(t, hover, "Should return nil for empty document")
}

func TestGetHover_UnknownWord(t *testing.T) {
	t.Parallel()
	hp, docs := newTestProvider()

	content := `- rule: Test
  desc: Test
  condition: totally_unknown_symbol
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
	analyzeDocument(doc)

	params := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "test.yaml"},
		Position:     protocol.Position{Line: 2, Character: 18}, // On "totally_unknown_symbol"
	}

	hover := hp.GetHover(doc, params)
	assert.Nil(t, hover, "Should return nil for unknown symbol")
}

func TestGetHover_MacroWithEmptyCondition(t *testing.T) {
	t.Parallel()
	hp, docs := newTestProvider()

	content := `- macro: empty_macro
  condition:

- rule: Test
  desc: Test
  condition: empty_macro
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
	analyzeDocument(doc)

	params := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "test.yaml"},
		Position:     protocol.Position{Line: 5, Character: 14}, // On "empty_macro"
	}

	hover := hp.GetHover(doc, params)
	if hover != nil {
		assert.Contains(t, hover.Contents.Value, "Macro: empty_macro", "Should contain macro name")
	}
}

func TestGetHover_ListWithEmptyItems(t *testing.T) {
	t.Parallel()
	hp, docs := newTestProvider()

	content := `- list: empty_list
  items: []

- rule: Test
  desc: Test
  condition: proc.name in (empty_list)
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
	analyzeDocument(doc)

	params := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "test.yaml"},
		Position:     protocol.Position{Line: 5, Character: 30}, // On "empty_list"
	}

	hover := hp.GetHover(doc, params)
	if hover != nil {
		assert.Contains(t, hover.Contents.Value, "List: empty_list", "Should contain list name")
	}
}

func TestGetHover_CrossFile(t *testing.T) {
	t.Parallel()
	hp, docs := newTestProvider()

	// File 1: defines macro
	content1 := `- macro: is_shell
  condition: proc.name in (bash, sh)
`
	result1, _ := parser.Parse(content1, "macros.yaml")
	doc1 := &document.Document{
		URI:     "macros.yaml",
		Content: content1,
		Version: 1,
		Result:  result1,
	}
	_ = docs.Set(doc1)
	analyzeDocument(doc1)

	// File 2: uses macro
	content2 := `- rule: Shell Spawn
  desc: Test
  condition: is_shell
  output: "shell"
  priority: INFO
`
	result2, _ := parser.Parse(content2, "rules.yaml")
	doc2 := &document.Document{
		URI:     "rules.yaml",
		Content: content2,
		Version: 1,
		Result:  result2,
	}
	_ = docs.Set(doc2)
	analyzeDocument(doc2)

	params := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "rules.yaml"},
		Position:     protocol.Position{Line: 2, Character: 14}, // On "is_shell"
	}

	hover := hp.GetHover(doc2, params)
	require.NotNil(t, hover, "Should find cross-file macro hover")
	assert.Contains(t, hover.Contents.Value, "Macro: is_shell", "Should contain macro name")
	assert.Contains(t, hover.Contents.Value, "proc.name in (bash, sh)", "Should contain condition")
}

func TestFormatListPreview_Empty(t *testing.T) {
	t.Parallel()
	result := formatListPreview(nil)
	assert.Equal(t, "", result, "Empty list should return empty string")
}

func TestFormatListPreview_FewItems(t *testing.T) {
	t.Parallel()
	result := formatListPreview([]string{"a", "b", "c"})
	assert.Contains(t, result, "a", "Should contain items")
	assert.Contains(t, result, "b", "Should contain items")
	assert.Contains(t, result, "c", "Should contain items")
}

func TestFormatListPreview_ManyItems(t *testing.T) {
	t.Parallel()
	items := make([]string, 20)
	for i := range items {
		items[i] = "item"
	}
	result := formatListPreview(items)
	assert.Contains(t, result, "more", "Should indicate truncation for many items")
}

func TestNewMarkdownHover(t *testing.T) {
	t.Parallel()
	hover := newMarkdownHover("test content")
	require.NotNil(t, hover)
	assert.Equal(t, protocol.MarkupKindMarkdown, hover.Contents.Kind)
	assert.Equal(t, "test content", hover.Contents.Value)
}

func TestGetHover_FdNameField(t *testing.T) {
	t.Parallel()
	hp, docs := newTestProvider()

	content := `- rule: Test
  desc: Test
  condition: fd.name contains /etc
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
	analyzeDocument(doc)

	params := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "test.yaml"},
		Position:     protocol.Position{Line: 2, Character: 14}, // On "fd.name"
	}

	hover := hp.GetHover(doc, params)
	require.NotNil(t, hover, "Should return hover for fd.name field")
	assert.Contains(t, hover.Contents.Value, "fd.name", "Should contain field name")
}
