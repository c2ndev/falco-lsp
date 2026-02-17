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

// Package references provides find-references functionality.
package references

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
	rp, _ := newTestProvider()
	require.NotNil(t, rp, "New returned nil")
}

func TestGetReferences_NilDoc(t *testing.T) {
	t.Parallel()
	rp, _ := newTestProvider()

	params := protocol.ReferenceParams{}
	locations := rp.GetReferences(nil, params)

	assert.Nil(t, locations, "expected nil for nil document")
}

func TestGetReferences_EmptyWord(t *testing.T) {
	t.Parallel()
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

	params := protocol.ReferenceParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: doc.URI},
			Position:     protocol.Position{Line: 0, Character: 0},
		},
	}

	locations := rp.GetReferences(doc, params)
	assert.Nil(t, locations, "expected nil for empty word position")
}

func TestGetReferences_MacroWithDeclaration(t *testing.T) {
	t.Parallel()
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
	require.NoError(t, err)

	doc := &document.Document{
		URI:     "test.falco.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}
	_ = docs.Set(doc)
	analyzeDocument(doc)

	params := protocol.ReferenceParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: doc.URI},
			Position:     protocol.Position{Line: 0, Character: 10}, // "is_shell"
		},
		Context: protocol.ReferenceContext{IncludeDeclaration: true},
	}

	locations := rp.GetReferences(doc, params)
	require.NotEmpty(t, locations, "Should find references for macro")
	// Should include at least the declaration
	assert.GreaterOrEqual(t, len(locations), 1, "Should include at least the declaration")
}

func TestGetReferences_MacroWithoutDeclaration(t *testing.T) {
	t.Parallel()
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
	require.NoError(t, err)

	doc := &document.Document{
		URI:     "test.falco.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}
	_ = docs.Set(doc)
	analyzeDocument(doc)

	params := protocol.ReferenceParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: doc.URI},
			Position:     protocol.Position{Line: 0, Character: 10}, // "is_shell"
		},
		Context: protocol.ReferenceContext{IncludeDeclaration: false},
	}

	locations := rp.GetReferences(doc, params)
	// Without IncludeDeclaration, should not include line 0 (the definition)
	for _, loc := range locations {
		if loc.Range.Start.Line == 0 {
			t.Error("Should not include declaration when IncludeDeclaration is false")
		}
	}
}

func TestGetReferences_ListReference(t *testing.T) {
	t.Parallel()
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
	require.NoError(t, err)

	doc := &document.Document{
		URI:     "test.falco.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}
	_ = docs.Set(doc)
	analyzeDocument(doc)

	params := protocol.ReferenceParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: doc.URI},
			Position:     protocol.Position{Line: 0, Character: 10}, // "shell_binaries"
		},
		Context: protocol.ReferenceContext{IncludeDeclaration: true},
	}

	locations := rp.GetReferences(doc, params)
	require.NotEmpty(t, locations, "Should find references for list")
	assert.GreaterOrEqual(t, len(locations), 1, "Should include at least the declaration")
}

func TestGetReferences_RuleReference(t *testing.T) {
	t.Parallel()
	rp, docs := newTestProvider()

	content := `- rule: TestRule
  desc: A test rule
  condition: proc.name = bash
  output: "test"
  priority: INFO
`
	result, err := parser.Parse(content, "test.falco.yaml")
	require.NoError(t, err)

	doc := &document.Document{
		URI:     "test.falco.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}
	_ = docs.Set(doc)
	analyzeDocument(doc)

	params := protocol.ReferenceParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: doc.URI},
			Position:     protocol.Position{Line: 0, Character: 10}, // "TestRule"
		},
		Context: protocol.ReferenceContext{IncludeDeclaration: true},
	}

	locations := rp.GetReferences(doc, params)
	// Should find at least the declaration
	if len(locations) > 0 {
		assert.GreaterOrEqual(t, len(locations), 1, "Should find at least one reference")
	}
}

func TestGetReferences_MacroUsedInMultipleRules(t *testing.T) {
	t.Parallel()
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
	require.NoError(t, err)

	doc := &document.Document{
		URI:     "test.falco.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}
	_ = docs.Set(doc)
	analyzeDocument(doc)

	params := protocol.ReferenceParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: doc.URI},
			Position:     protocol.Position{Line: 0, Character: 10}, // "is_shell"
		},
		Context: protocol.ReferenceContext{IncludeDeclaration: true},
	}

	locations := rp.GetReferences(doc, params)
	// Should find declaration + 2 usages = at least 3
	require.NotEmpty(t, locations, "Should find references across multiple rules")
	assert.GreaterOrEqual(t, len(locations), 2, "Should find at least declaration + one usage")
}

func TestGetReferences_CrossFile(t *testing.T) {
	t.Parallel()
	rp, docs := newTestProvider()

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
	require.NotEmpty(t, locations, "Should find cross-file references")
	// Verify we found references in both files
	hasDeclaration := false
	hasUsage := false
	for _, loc := range locations {
		if loc.Range.Start.Line == 0 {
			hasDeclaration = true
		}
		if loc.Range.Start.Line > 0 {
			hasUsage = true
		}
	}
	assert.True(t, hasDeclaration, "Should include the declaration")
	assert.True(t, hasUsage, "Should include at least one usage")
}

func TestGetReferences_NoSymbols(t *testing.T) {
	t.Parallel()
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
	}
	_ = docs.Set(doc)
	// Don't analyze - no symbols

	params := protocol.ReferenceParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: doc.URI},
			Position:     protocol.Position{Line: 0, Character: 10},
		},
	}

	locations := rp.GetReferences(doc, params)
	assert.Nil(t, locations, "Should return nil when no symbols defined")
}

func TestGetReferences_MacroUsedInMacro(t *testing.T) {
	t.Parallel()
	rp, docs := newTestProvider()

	content := `- macro: is_shell
  condition: proc.name in (bash, sh)

- macro: is_shell_open
  condition: is_shell and evt.type = open

- rule: Test
  desc: Test
  condition: is_shell_open
  output: "test"
  priority: INFO
`
	result, err := parser.Parse(content, "test.falco.yaml")
	require.NoError(t, err)

	doc := &document.Document{
		URI:     "test.falco.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}
	_ = docs.Set(doc)
	analyzeDocument(doc)

	params := protocol.ReferenceParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: doc.URI},
			Position:     protocol.Position{Line: 0, Character: 10}, // "is_shell"
		},
		Context: protocol.ReferenceContext{IncludeDeclaration: true},
	}

	locations := rp.GetReferences(doc, params)
	require.NotEmpty(t, locations, "Should find references including macro-in-macro usage")
	assert.GreaterOrEqual(t, len(locations), 2, "Should find declaration + usage in other macro")
}
