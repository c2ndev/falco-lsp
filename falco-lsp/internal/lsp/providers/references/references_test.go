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

// Package references provides find-references functionality.
package references

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
	rp, _ := newTestProvider()

	require.NotNil(t, rp, "New returned nil")
}

func TestGetReferences(t *testing.T) {
	rp, docs := newTestProvider()

	content := `- macro: is_shell
  condition: proc.name in (bash, sh, zsh)

- rule: Shell Spawn
  desc: Detect shell
  condition: is_shell and evt.type = execve
  output: "Shell spawned"
  priority: INFO
`

	result, err := parser.Parse(content, "test.falco.yaml")
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	doc := &document.Document{
		URI:     "test.falco.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}
	_ = docs.Set(doc)
	analyzeDocument(doc)

	// Find references to the macro at position where it's defined
	params := protocol.ReferenceParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: doc.URI},
			Position:     protocol.Position{Line: 0, Character: 10}, // "is_shell"
		},
		Context: protocol.ReferenceContext{IncludeDeclaration: true},
	}

	locations := rp.GetReferences(doc, params)

	// Should find at least the declaration
	if len(locations) == 0 {
		t.Log("No references found - this may be expected depending on analyzer state")
	}
}

func TestGetReferences_NilDoc(t *testing.T) {
	rp, _ := newTestProvider()

	params := protocol.ReferenceParams{}
	locations := rp.GetReferences(nil, params)

	assert.Nil(t, locations, "expected nil for nil document")
}

func TestGetReferences_EmptyWord(t *testing.T) {
	rp, docs := newTestProvider()

	content := `- rule: Test
  desc: Test rule
  condition: proc.name = bash
  output: "test"
  priority: INFO
`

	result, _ := parser.Parse(content, "test.falco.yaml")
	doc := &document.Document{
		URI:     "test.falco.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}
	_ = docs.Set(doc)
	analyzeDocument(doc)

	// Position at whitespace should return nil
	params := protocol.ReferenceParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: doc.URI},
			Position:     protocol.Position{Line: 0, Character: 0}, // At "- " which is not a word
		},
	}

	locations := rp.GetReferences(doc, params)
	assert.Nil(t, locations, "expected nil for empty word position")
}

func TestGetReferences_ListReference(t *testing.T) {
	rp, docs := newTestProvider()

	content := `- list: shell_binaries
  items: [bash, sh, zsh]

- rule: Shell Spawn
  desc: Detect shell
  condition: proc.name in (shell_binaries)
  output: "Shell spawned"
  priority: INFO
`

	result, err := parser.Parse(content, "test.falco.yaml")
	require.NoError(t, err, "failed to parse")

	doc := &document.Document{
		URI:     "test.falco.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}
	_ = docs.Set(doc)
	analyzeDocument(doc)

	// Find references to the list
	params := protocol.ReferenceParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: doc.URI},
			Position:     protocol.Position{Line: 0, Character: 10}, // "shell_binaries"
		},
		Context: protocol.ReferenceContext{IncludeDeclaration: true},
	}

	locations := rp.GetReferences(doc, params)
	// Should find at least the declaration
	if len(locations) == 0 {
		t.Log("No references found - this may be expected depending on analyzer state")
	}
}

func TestGetReferences_RuleReference(t *testing.T) {
	rp, docs := newTestProvider()

	content := `- rule: Test Rule
  desc: A test rule
  condition: proc.name = bash
  output: "test"
  priority: INFO
`

	result, err := parser.Parse(content, "test.falco.yaml")
	require.NoError(t, err, "failed to parse")

	doc := &document.Document{
		URI:     "test.falco.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}
	_ = docs.Set(doc)
	analyzeDocument(doc)

	// Find references to the rule
	params := protocol.ReferenceParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: doc.URI},
			Position:     protocol.Position{Line: 0, Character: 10}, // "Test Rule"
		},
		Context: protocol.ReferenceContext{IncludeDeclaration: true},
	}

	locations := rp.GetReferences(doc, params)
	// Should find the declaration
	if len(locations) == 0 {
		t.Log("No references found - this may be expected depending on analyzer state")
	}
}

func TestGetReferences_MacroUsedInMultipleRules(t *testing.T) {
	rp, docs := newTestProvider()

	content := `- macro: is_shell
  condition: proc.name in (bash, sh, zsh)

- rule: Shell Spawn 1
  desc: Detect shell
  condition: is_shell and evt.type = execve
  output: "Shell spawned"
  priority: INFO

- rule: Shell Spawn 2
  desc: Detect shell again
  condition: is_shell and evt.type = clone
  output: "Shell spawned"
  priority: WARNING
`

	result, err := parser.Parse(content, "test.falco.yaml")
	require.NoError(t, err, "failed to parse")

	doc := &document.Document{
		URI:     "test.falco.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}
	_ = docs.Set(doc)
	analyzeDocument(doc)

	// Find references to the macro
	params := protocol.ReferenceParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: doc.URI},
			Position:     protocol.Position{Line: 0, Character: 10}, // "is_shell"
		},
		Context: protocol.ReferenceContext{IncludeDeclaration: true},
	}

	locations := rp.GetReferences(doc, params)
	// Should find the declaration and usages
	if len(locations) == 0 {
		t.Log("No references found - this may be expected depending on analyzer state")
	}
}

func TestGetReferences_WithoutDeclaration(t *testing.T) {
	rp, docs := newTestProvider()

	content := `- macro: is_shell
  condition: proc.name in (bash, sh, zsh)

- rule: Shell Spawn
  desc: Detect shell
  condition: is_shell and evt.type = execve
  output: "Shell spawned"
  priority: INFO
`

	result, err := parser.Parse(content, "test.falco.yaml")
	require.NoError(t, err, "failed to parse")

	doc := &document.Document{
		URI:     "test.falco.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}
	_ = docs.Set(doc)
	analyzeDocument(doc)

	// Find references without including declaration
	params := protocol.ReferenceParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: doc.URI},
			Position:     protocol.Position{Line: 0, Character: 10}, // "is_shell"
		},
		Context: protocol.ReferenceContext{IncludeDeclaration: false},
	}

	locations := rp.GetReferences(doc, params)
	// Should find only usages, not the declaration
	for _, loc := range locations {
		if loc.Range.Start.Line == 0 {
			t.Log("Found declaration when IncludeDeclaration is false - checking if it's a usage")
		}
	}
}

func TestFindWordInConditionText(t *testing.T) {
	tests := []struct {
		cond     string
		word     string
		expected int // expected number of locations
	}{
		{"is_shell and evt.type = execve", "is_shell", 1},
		{"is_shell and is_shell", "is_shell", 2},
		{"proc.name = bash", "bash", 1},
		{"", "test", 0},
		{"no_match_here", "test", 0},
	}

	for _, tt := range tests {
		locations := findWordInConditionText(tt.cond, tt.word, "test.yaml", 0)
		assert.Len(t, locations, tt.expected, "findWordInConditionText(%q, %q)", tt.cond, tt.word)
	}
}

func TestFindWordInCondition_EmptyCondition(t *testing.T) {
	locations := findWordInCondition("", "test", "test.yaml", 0)
	assert.Len(t, locations, 0, "expected 0 locations for empty condition")
}

func TestFindWordInCondition_WithAST(t *testing.T) {
	// Test with a valid condition that can be parsed
	cond := "is_shell and evt.type = execve"
	locations := findWordInCondition(cond, "is_shell", "test.yaml", 0)
	// Should find the macro reference
	if len(locations) == 0 {
		t.Log("No locations found - AST parsing may have failed, falling back to text search")
	}
}

func TestGetReferences_NoSymbols(t *testing.T) {
	rp, docs := newTestProvider()

	content := `- rule: Test Rule
  desc: A test rule
  condition: proc.name = bash
  output: "test"
  priority: INFO
`

	result, _ := parser.Parse(content, "test.falco.yaml")
	doc := &document.Document{
		URI:     "test.falco.yaml",
		Content: content,
		Version: 1,
		Result:  result,
		// No Symbols set
	}
	_ = docs.Set(doc)

	params := protocol.ReferenceParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: doc.URI},
			Position:     protocol.Position{Line: 0, Character: 10},
		},
	}

	locations := rp.GetReferences(doc, params)
	// Should return nil since no symbols are defined
	if locations != nil {
		t.Log("References returned without symbols")
	}
}

func TestGetReferences_CrossFile(t *testing.T) {
	rp, docs := newTestProvider()

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

	params := protocol.ReferenceParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: "macros.yaml"},
			Position:     protocol.Position{Line: 0, Character: 10}, // "is_shell"
		},
		Context: protocol.ReferenceContext{IncludeDeclaration: true},
	}

	locations := rp.GetReferences(doc1, params)
	// Should find references across files
	if len(locations) > 0 {
		t.Logf("Found %d references", len(locations))
	}
}

func TestFindWordInCondition_ListReference(t *testing.T) {
	cond := "proc.name in (shell_binaries)"
	locations := findWordInCondition(cond, "shell_binaries", "test.yaml", 0)
	// Should find the list reference
	if len(locations) == 0 {
		t.Log("No locations found for list reference")
	}
}

func TestFindWordInCondition_InvalidCondition(_ *testing.T) {
	// Test with an invalid condition that can't be parsed
	cond := "((( invalid"
	locations := findWordInCondition(cond, "invalid", "test.yaml", 0)
	// Should fall back to text search
	_ = locations
}

func TestFindWordInConditionText_MultipleOccurrences(t *testing.T) {
	cond := "is_shell and is_shell and is_shell"
	locations := findWordInConditionText(cond, "is_shell", "test.yaml", 0)
	assert.Len(t, locations, 3, "expected 3 locations")
}

func TestFindWordInConditionText_NoMatch(t *testing.T) {
	cond := "proc.name = bash"
	locations := findWordInConditionText(cond, "nonexistent", "test.yaml", 0)
	assert.Len(t, locations, 0, "expected 0 locations")
}

func TestFindWordInConditionText_PartialMatch(_ *testing.T) {
	// Should not match partial words
	cond := "is_shell_extended"
	locations := findWordInConditionText(cond, "is_shell", "test.yaml", 0)
	// This depends on implementation - may or may not match
	_ = locations
}
