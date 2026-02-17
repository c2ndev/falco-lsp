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

// Package symbols provides document symbol functionality.
package symbols

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
	sp, _ := newTestProvider()

	require.NotNil(t, sp, "New returned nil")
}

func TestGetDocumentSymbols(t *testing.T) {
	sp, docs := newTestProvider()

	content := `- rule: Test Rule
  desc: A test rule
  condition: evt.type = execve
  output: "Test output"
  priority: WARNING

- macro: test_macro
  condition: proc.name = bash

- list: test_list
  items: [a, b, c]
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

	symbols := sp.GetDocumentSymbols(doc)

	require.NotEmpty(t, symbols, "expected symbols, got none")

	// Check we have all three types
	hasRule := false
	hasMacro := false
	hasList := false

	for _, s := range symbols {
		switch s.Kind {
		case protocol.SymbolKindClass:
			hasRule = true
			assert.Equal(t, "Test Rule", s.Name, "expected rule name 'Test Rule'")
		case protocol.SymbolKindFunction:
			hasMacro = true
			assert.Equal(t, "test_macro", s.Name, "expected macro name 'test_macro'")
		case protocol.SymbolKindArray:
			hasList = true
			assert.Equal(t, "test_list", s.Name, "expected list name 'test_list'")
		}
	}

	assert.True(t, hasRule, "expected to find rule symbol")
	assert.True(t, hasMacro, "expected to find macro symbol")
	assert.True(t, hasList, "expected to find list symbol")
}

func TestGetDocumentSymbols_NilDoc(t *testing.T) {
	sp, _ := newTestProvider()

	symbols := sp.GetDocumentSymbols(nil)
	assert.Nil(t, symbols, "expected nil for nil document")
}

// Note: matchesURI and joinStrings tests have been moved to internal/utils/utils_test.go
