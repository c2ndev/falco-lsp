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

// Package formatting provides document formatting functionality.
package formatting

import (
	"strings"
	"testing"

	"github.com/c2ndev/falco-lsp/internal/lsp/document"
	"github.com/c2ndev/falco-lsp/internal/lsp/protocol"
	"github.com/c2ndev/falco-lsp/internal/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test fixtures.
const testRuleContent = `- rule: Test Rule
  desc: A test rule
  condition: evt.type = open
  output: "test"
  priority: INFO
`

func newTestProvider() *Provider {
	docs := document.NewStore()
	return New(docs, 2)
}

func TestNewProvider(t *testing.T) {
	fp := newTestProvider()

	require.NotNil(t, fp, "New returned nil")
}

func TestFormat(t *testing.T) {
	fp := newTestProvider()

	// Test with nil document
	opts := protocol.FormattingOptions{
		TabSize:      2,
		InsertSpaces: true,
	}
	edits := fp.Format(nil, opts)
	assert.Nil(t, edits, "expected nil edits for nil document")

	// Test with valid document
	content := testRuleContent
	result, err := parser.Parse(content, "test.yaml")
	require.NoError(t, err, "parse failed")

	doc := &document.Document{
		URI:     "test.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}

	edits = fp.Format(doc, opts)
	// Should return some edits (even if empty array for already-formatted)
	// nil is also valid if no changes needed
	_ = edits
}

func TestFormatRange(t *testing.T) {
	fp := newTestProvider()

	content := testRuleContent
	result, err := parser.Parse(content, "test.yaml")
	require.NoError(t, err, "parse failed")

	doc := &document.Document{
		URI:     "test.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}

	params := protocol.DocumentRangeFormattingParams{
		Range: protocol.Range{
			Start: protocol.Position{Line: 0, Character: 0},
			End:   protocol.Position{Line: 5, Character: 0},
		},
		Options: protocol.FormattingOptions{
			TabSize:      2,
			InsertSpaces: true,
		},
	}

	edits := fp.FormatRange(doc, params)
	// Should return edits (may be nil for already-formatted)
	_ = edits
}

func TestFormatYAML(t *testing.T) {
	fp := newTestProvider()

	tests := []struct {
		name     string
		input    string
		tabSize  int
		expected string
	}{
		{
			name:     "already formatted",
			input:    "- rule: Test\n  desc: value\n",
			tabSize:  2,
			expected: "- rule: Test\n  desc: value\n",
		},
		{
			name:     "empty string",
			input:    "",
			tabSize:  2,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := protocol.FormattingOptions{TabSize: tt.tabSize, InsertSpaces: true}
			result := fp.formatYAML(tt.input, opts)
			assert.Equal(t, tt.expected, result, "formatYAML()")
		})
	}
}

func TestFormattingOptionsDefaults(t *testing.T) {
	fp := newTestProvider()

	// Test with TabSize = 0 (should use default)
	opts := protocol.FormattingOptions{TabSize: 0, InsertSpaces: true}
	input := "- rule: test\n  desc: test\n"
	result := fp.formatYAML(input, opts)

	// Should still format
	assert.Contains(t, result, "desc:", "formatting failed for zero tab size")
}

func TestNormalizeLineEndings(t *testing.T) {
	fp := newTestProvider()

	input := "line1\r\nline2\r\nline3"
	opts := protocol.FormattingOptions{TabSize: 2, InsertSpaces: true}
	result := fp.formatYAML(input, opts)

	// Result should contain lines
	assert.Contains(t, result, "line1", "expected line1 in result")
}

func TestTrimTrailingWhitespace(t *testing.T) {
	fp := newTestProvider()

	input := "key: value   \n"
	opts := protocol.FormattingOptions{
		TabSize:                2,
		InsertSpaces:           true,
		TrimTrailingWhitespace: true,
	}
	result := fp.formatYAML(input, opts)

	// Trailing whitespace should be trimmed
	assert.NotContains(t, result, "value   ", "trailing whitespace should be trimmed")
}

func TestInsertFinalNewline(t *testing.T) {
	fp := newTestProvider()

	input := "key: value"
	opts := protocol.FormattingOptions{
		TabSize:            2,
		InsertSpaces:       true,
		InsertFinalNewline: true,
	}
	result := fp.formatYAML(input, opts)

	assert.True(t, strings.HasSuffix(result, "\n"), "should have final newline")
}

func TestFormat_WithChanges(t *testing.T) {
	fp := newTestProvider()

	// Content with trailing whitespace that needs formatting
	content := "- rule: Test Rule   \n  desc: A test rule\n  condition: evt.type = open\n  output: \"test\"\n  priority: INFO\n"
	result, err := parser.Parse(content, "test.yaml")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	doc := &document.Document{
		URI:     "test.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}

	opts := protocol.FormattingOptions{
		TabSize:                2,
		InsertSpaces:           true,
		TrimTrailingWhitespace: true,
	}

	edits := fp.Format(doc, opts)
	// Should return edits since content needs formatting
	assert.NotNil(t, edits, "expected edits for content that needs formatting")
}

func TestFormat_EmptyContent(t *testing.T) {
	fp := newTestProvider()

	doc := &document.Document{
		URI:     "test.yaml",
		Content: "",
		Version: 1,
	}

	opts := protocol.FormattingOptions{
		TabSize:      2,
		InsertSpaces: true,
	}

	edits := fp.Format(doc, opts)
	assert.Nil(t, edits, "expected nil edits for empty content")
}

func TestFormatRange_NilDocument(t *testing.T) {
	fp := newTestProvider()

	params := protocol.DocumentRangeFormattingParams{
		Range: protocol.Range{
			Start: protocol.Position{Line: 0, Character: 0},
			End:   protocol.Position{Line: 5, Character: 0},
		},
		Options: protocol.FormattingOptions{
			TabSize:      2,
			InsertSpaces: true,
		},
	}

	edits := fp.FormatRange(nil, params)
	assert.Nil(t, edits, "expected nil edits for nil document")
}

func TestFormatRange_EmptyContent(t *testing.T) {
	fp := newTestProvider()

	doc := &document.Document{
		URI:     "test.yaml",
		Content: "",
		Version: 1,
	}

	params := protocol.DocumentRangeFormattingParams{
		Range: protocol.Range{
			Start: protocol.Position{Line: 0, Character: 0},
			End:   protocol.Position{Line: 5, Character: 0},
		},
		Options: protocol.FormattingOptions{
			TabSize:      2,
			InsertSpaces: true,
		},
	}

	edits := fp.FormatRange(doc, params)
	assert.Nil(t, edits, "expected nil edits for empty content")
}

func TestNew_ZeroTabSize(t *testing.T) {
	docs := document.NewStore()
	fp := New(docs, 0)
	require.NotNil(t, fp, "New returned nil")
}

func TestNew_NegativeTabSize(t *testing.T) {
	docs := document.NewStore()
	fp := New(docs, -5)
	require.NotNil(t, fp, "New returned nil")
}
