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

// Package lsp provides end-to-end integration tests for the LSP server.
package lsp

import (
	"strings"
	"testing"

	"github.com/c2ndev/falco-lsp/internal/analyzer"
	"github.com/c2ndev/falco-lsp/internal/lsp/document"
	"github.com/c2ndev/falco-lsp/internal/lsp/protocol"
	"github.com/c2ndev/falco-lsp/internal/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test content constants.
const testSimpleRuleContent = `- rule: Test
  desc: test
  condition: evt.type = open
  output: "test"
  priority: INFO
`

// analyzeDocumentForTest analyzes a document and populates its Symbols field.
// This helper is used in tests to simulate what the diagnostics provider does.
func analyzeDocumentForTest(doc *document.Document) {
	if doc.Result == nil || doc.Result.Document == nil {
		return
	}
	a := analyzer.NewAnalyzer()
	result := a.Analyze(doc.Result.Document, doc.URI)
	doc.Symbols = result.Symbols
}

// TestFullWorkflow tests a complete user workflow scenario.
func TestFullWorkflow(t *testing.T) {
	server := NewServer()

	// Step 1: Open a document
	content := `- macro: shell_procs
  condition: proc.name in (bash, sh, zsh)

- list: sensitive_files
  items: [/etc/passwd, /etc/shadow]

- rule: Shell Read Sensitive
  desc: Detect shell reading sensitive files
  condition: shell_procs and fd.name in (sensitive_files)
  output: "Shell %proc.name read %fd.name"
  priority: WARNING
`
	result, err := parser.Parse(content, "file:///test.yaml")
	require.NoError(t, err, "failed to parse")

	doc := &document.Document{
		URI:     "file:///test.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}
	_ = server.Documents().Set(doc)

	// Step 2: Analyze document
	analyzeDocumentForTest(doc)

	// Step 3: Request document symbols
	symbols := server.Symbols().GetDocumentSymbols(doc)
	assert.Len(t, symbols, 3, "expected 3 symbols (macro, list, rule)")

	// Step 4: Request hover on macro
	hoverParams := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.yaml"},
		Position:     protocol.Position{Line: 0, Character: 10}, // "shell_procs"
	}
	hover := server.Hover().GetHover(doc, hoverParams)
	assert.NotNil(t, hover, "expected hover result for macro name")

	// Step 5: Request go-to-definition from rule condition
	defParams := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.yaml"},
		Position:     protocol.Position{Line: 8, Character: 14}, // "shell_procs" in condition
	}
	location := server.Definition().GetDefinition(doc, defParams)
	require.NotNil(t, location, "expected definition location for macro reference")
	assert.Equal(t, 0, location.Range.Start.Line, "expected definition on line 0")

	// Step 6: Request references
	refParams := protocol.ReferenceParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.yaml"},
			Position:     protocol.Position{Line: 0, Character: 10}, // "shell_procs"
		},
		Context: protocol.ReferenceContext{IncludeDeclaration: true},
	}
	refs := server.References().GetReferences(doc, refParams)
	assert.GreaterOrEqual(t, len(refs), 2, "expected at least 2 references (definition + usage)")
}

// TestMultipleDocuments tests working with multiple documents simultaneously.
func TestMultipleDocuments(t *testing.T) {
	server := NewServer()

	// Document 1: Defines a macro
	content1 := `- macro: common_macro
  condition: container.id != host
`
	result1, _ := parser.Parse(content1, "file:///doc1.yaml")
	doc1 := &document.Document{
		URI:     "file:///doc1.yaml",
		Content: content1,
		Version: 1,
		Result:  result1,
	}
	_ = server.Documents().Set(doc1)
	analyzeDocumentForTest(doc1)

	// Document 2: Uses the macro
	content2 := `- rule: Use Common
  desc: Test
  condition: common_macro and evt.type = execve
  output: "test"
  priority: INFO
`
	result2, _ := parser.Parse(content2, "file:///doc2.yaml")
	doc2 := &document.Document{
		URI:     "file:///doc2.yaml",
		Content: content2,
		Version: 1,
		Result:  result2,
	}
	_ = server.Documents().Set(doc2)
	analyzeDocumentForTest(doc2)

	// Should find macro definition from doc2
	defParams := protocol.TextDocumentPositionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "file:///doc2.yaml"},
		Position:     protocol.Position{Line: 2, Character: 14}, // "common_macro"
	}
	location := server.Definition().GetDefinition(doc2, defParams)
	require.NotNil(t, location, "expected to find macro definition across documents")
	assert.Equal(t, "file:///doc1.yaml", location.URI, "expected definition in doc1")
}

// TestDocumentUpdates tests incremental document updates.
func TestDocumentUpdates(t *testing.T) {
	server := NewServer()

	// Initial content
	content := testSimpleRuleContent
	result, _ := parser.Parse(content, "file:///test.yaml")
	doc := &document.Document{
		URI:     "file:///test.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}
	_ = server.Documents().Set(doc)
	analyzeDocumentForTest(doc)

	symbols := server.Symbols().GetDocumentSymbols(doc)
	initialCount := len(symbols)

	// Update: Add a macro
	newContent := `- macro: is_open
  condition: evt.type = open

- rule: Test
  desc: test
  condition: is_open
  output: "test"
  priority: INFO
`
	newResult, _ := parser.Parse(newContent, "file:///test.yaml")
	doc.Content = newContent
	doc.Version = 2
	doc.Result = newResult
	_ = server.Documents().Set(doc)
	analyzeDocumentForTest(doc)

	symbols = server.Symbols().GetDocumentSymbols(doc)
	// After adding a macro, we should have more symbols than before
	assert.Greater(t, len(symbols), initialCount, "expected more symbols after adding macro")
}

// TestCompletionScenarios tests various completion scenarios.
func TestCompletionScenarios(t *testing.T) {
	server := NewServer()

	tests := []struct {
		name     string
		content  string
		line     int
		char     int
		minItems int
	}{
		{
			name: "field completion after evt.",
			content: `- rule: Test
  desc: test
  condition: evt.
  output: "test"
  priority: INFO
`,
			line:     2,
			char:     16,
			minItems: 0, // May be empty, just test no crash
		},
		{
			name: "field completion after proc.",
			content: `- rule: Test
  desc: test
  condition: proc.
  output: "test"
  priority: INFO
`,
			line:     2,
			char:     17,
			minItems: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _ := parser.Parse(tt.content, "file:///test.yaml")
			doc := &document.Document{
				URI:     "file:///test.yaml",
				Content: tt.content,
				Version: 1,
				Result:  result,
			}
			_ = server.Documents().Set(doc)

			params := protocol.CompletionParams{
				TextDocumentPositionParams: protocol.TextDocumentPositionParams{
					TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.yaml"},
					Position:     protocol.Position{Line: tt.line, Character: tt.char},
				},
			}

			items := server.Completion().GetCompletions(doc, params)
			assert.GreaterOrEqual(t, len(items), tt.minItems, "expected at least minItems completions")
		})
	}
}

// TestFormattingPreservesContent tests that formatting doesn't corrupt content.
func TestFormattingPreservesContent(t *testing.T) {
	server := NewServer()

	content := testSimpleRuleContent
	result, _ := parser.Parse(content, "file:///test.yaml")
	doc := &document.Document{
		URI:     "file:///test.yaml",
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

	// Apply edits and verify valid YAML
	if len(edits) > 0 {
		newContent := applyEdits(content, edits)
		// Should still be parseable
		_, err := parser.Parse(newContent, "file:///test.yaml")
		assert.NoError(t, err, "formatted content should be valid")
	}
}

// TestDiagnosticsIntegration tests diagnostics publishing.
func TestDiagnosticsIntegration(t *testing.T) {
	server := NewServer()

	// Valid rule - analyzer should process without crashing
	content := `- rule: Test
  desc: A test rule
  condition: evt.type = open
  output: "test output"
  priority: WARNING
`
	result, _ := parser.Parse(content, "file:///test.yaml")
	doc := &document.Document{
		URI:     "file:///test.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}
	_ = server.Documents().Set(doc)

	// Analyze should complete without error
	analyzeDocumentForTest(doc)

	// Just verify analyzer set symbols (diagnostics may or may not be present)
	assert.NotNil(t, doc.Symbols, "expected symbols to be populated")
}

// TestConcurrentAccess tests thread safety of document operations.
func TestConcurrentAccess(_ *testing.T) {
	server := NewServer()

	content := testSimpleRuleContent
	result, _ := parser.Parse(content, "file:///test.yaml")
	doc := &document.Document{
		URI:     "file:///test.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}
	_ = server.Documents().Set(doc)

	done := make(chan bool)

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				server.Documents().Get("file:///test.yaml")
				server.Symbols().GetDocumentSymbols(doc)
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// applyEdits applies text edits to content.
func applyEdits(content string, edits []protocol.TextEdit) string {
	lines := strings.Split(content, "\n")

	// Apply edits in reverse order to maintain positions
	for i := len(edits) - 1; i >= 0; i-- {
		edit := edits[i]
		startLine := edit.Range.Start.Line
		endLine := edit.Range.End.Line

		if startLine >= len(lines) || endLine >= len(lines) {
			continue
		}

		// Simple single-line replace
		if startLine == endLine {
			line := lines[startLine]
			before := ""
			if edit.Range.Start.Character < len(line) {
				before = line[:edit.Range.Start.Character]
			}
			after := ""
			if edit.Range.End.Character < len(line) {
				after = line[edit.Range.End.Character:]
			}
			lines[startLine] = before + edit.NewText + after
		}
	}

	return strings.Join(lines, "\n")
}
