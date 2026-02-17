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

// Package definition provides go-to-definition functionality.
package definition

import (
	"testing"

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
	dp, _ := newTestProvider()

	require.NotNil(t, dp, "New returned nil")
}

func TestGetDefinition_Macro(t *testing.T) {
	dp, docs := newTestProvider()

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

	location := dp.GetDefinition(doc, params)
	require.NotNil(t, location, "Should find macro definition")
	require.Equal(t, 0, location.Range.Start.Line, "Macro definition should be on line 0")
}

func TestGetDefinition_NilDoc(t *testing.T) {
	dp, _ := newTestProvider()

	params := protocol.TextDocumentPositionParams{}
	location := dp.GetDefinition(nil, params)

	require.Nil(t, location, "expected nil for nil document")
}

func TestDefinitionForList(t *testing.T) {
	dp, docs := newTestProvider()

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

	location := dp.GetDefinition(doc, params)
	require.NotNil(t, location, "Should find list definition")
	require.Equal(t, 0, location.Range.Start.Line, "List definition should be on line 0")
}

func TestDefinitionNotFound(t *testing.T) {
	dp, docs := newTestProvider()

	content := `- rule: Test
  desc: Test
  condition: undefined_macro
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
		Position:     protocol.Position{Line: 2, Character: 18}, // On "undefined_macro"
	}

	location := dp.GetDefinition(doc, params)
	require.Nil(t, location, "Should return nil for undefined symbol")
}

func TestDefinitionOnField(t *testing.T) {
	dp, docs := newTestProvider()

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
		Position:     protocol.Position{Line: 2, Character: 14}, // On "evt.type"
	}

	location := dp.GetDefinition(doc, params)
	// Fields don't have definitions in source - should return nil
	require.Nil(t, location, "Fields should not have definitions")
}

func TestDefinitionEmptyContent(t *testing.T) {
	dp, docs := newTestProvider()

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

	location := dp.GetDefinition(doc, params)
	require.Nil(t, location, "Empty content should return nil")
}

func TestDefinitionForRule(t *testing.T) {
	dp, docs := newTestProvider()

	// Use single-word rule names that GetWordAtPosition can capture
	content := `- rule: BaseRule
  desc: Base rule
  condition: evt.type = open
  output: "base"
  priority: INFO

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
		Position:     protocol.Position{Line: 8, Character: 14}, // On "BaseRule"
	}

	location := dp.GetDefinition(doc, params)
	require.NotNil(t, location, "Should find rule definition")
	require.Equal(t, 0, location.Range.Start.Line, "Rule definition should be on line 0")
}

func TestDefinitionCrossFile(t *testing.T) {
	dp, docs := newTestProvider()

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

	location := dp.GetDefinition(doc2, params)
	require.NotNil(t, location, "Should find cross-file macro definition")
	require.Contains(t, location.URI, "macros.yaml", "Should point to macros.yaml")
}

func TestDefinitionEmptyWord(t *testing.T) {
	dp, docs := newTestProvider()

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

	// Position on whitespace
	params := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "test.yaml"},
		Position:     protocol.Position{Line: 2, Character: 10}, // On "= " (space)
	}

	location := dp.GetDefinition(doc, params)
	require.Nil(t, location, "Should return nil for whitespace position")
}

func TestDefinitionNoSymbols(t *testing.T) {
	dp, docs := newTestProvider()

	content := `- rule: Test
  desc: Test
  condition: some_macro
  output: "test"
  priority: INFO
`
	result, _ := parser.Parse(content, "test.yaml")
	doc := &document.Document{
		URI:     "test.yaml",
		Content: content,
		Version: 1,
		Result:  result,
		// No Symbols set - don't analyze
	}
	_ = docs.Set(doc)

	params := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "test.yaml"},
		Position:     protocol.Position{Line: 2, Character: 14}, // On "some_macro"
	}

	location := dp.GetDefinition(doc, params)
	require.Nil(t, location, "Should return nil when no symbols defined")
}
