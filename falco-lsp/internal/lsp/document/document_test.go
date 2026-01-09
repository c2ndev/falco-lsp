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

// Package document provides document management for the LSP server.
package document

import (
	"testing"

	"github.com/c2ndev/falco-lsp/internal/analyzer"
	"github.com/c2ndev/falco-lsp/internal/lsp/protocol"
	"github.com/c2ndev/falco-lsp/internal/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStore(t *testing.T) {
	ds := NewStore()
	require.NotNil(t, ds)
	assert.Equal(t, 0, ds.Count())
}

func TestValidateURI(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr error
	}{
		{"valid file URI", "file:///path/to/file.yaml", nil},
		{"valid untitled URI", "untitled:Untitled-1", nil},
		{"valid plain path", "/path/to/file.yaml", nil},
		{"valid relative path", "test.yaml", nil},
		{"empty URI", "", ErrEmptyURI},
		{"path traversal", "file:///../../../etc/passwd", ErrInvalidURI},
		{"invalid scheme", "http://example.com/file.yaml", ErrInvalidScheme},
		{"ftp scheme", "ftp://server/file.yaml", ErrInvalidScheme},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateURI(tt.uri)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestStore_SetWithValidation(t *testing.T) {
	ds := NewStore()

	// Valid URI should succeed
	doc := &Document{
		URI:     "file:///test.yaml",
		Content: "content",
		Version: 1,
	}
	err := ds.Set(doc)
	assert.NoError(t, err)
	assert.Equal(t, 1, ds.Count())

	// Invalid URI should fail
	invalidDoc := &Document{
		URI:     "",
		Content: "content",
		Version: 1,
	}
	err = ds.Set(invalidDoc)
	assert.ErrorIs(t, err, ErrEmptyURI)
	assert.Equal(t, 1, ds.Count()) // Count should not change
}

func TestStore_SetAndGet(t *testing.T) {
	ds := NewStore()
	doc := &Document{
		URI:     "file:///test.yaml",
		Content: "- rule: Test\n  desc: Test rule",
		Version: 1,
	}

	err := ds.Set(doc)
	require.NoError(t, err)

	retrieved, ok := ds.Get("file:///test.yaml")
	assert.True(t, ok)
	assert.Equal(t, doc.Content, retrieved.Content)
	assert.Equal(t, 1, ds.Count())
}

func TestStore_GetNotFound(t *testing.T) {
	ds := NewStore()

	_, ok := ds.Get("file:///nonexistent.yaml")
	assert.False(t, ok)
}

func TestStore_Delete(t *testing.T) {
	ds := NewStore()
	doc := &Document{
		URI:     "file:///test.yaml",
		Content: "content",
		Version: 1,
	}

	_ = ds.Set(doc)
	assert.Equal(t, 1, ds.Count())

	ds.Delete("file:///test.yaml")
	assert.Equal(t, 0, ds.Count())

	_, ok := ds.Get("file:///test.yaml")
	assert.False(t, ok)
}

func TestStore_All(t *testing.T) {
	ds := NewStore()
	_ = ds.Set(&Document{URI: "file:///a.yaml", Content: "a"})
	_ = ds.Set(&Document{URI: "file:///b.yaml", Content: "b"})
	_ = ds.Set(&Document{URI: "file:///c.yaml", Content: "c"})

	all := ds.All()
	assert.Len(t, all, 3)
}

func TestDocument_ApplyContentChanges_FullSync(t *testing.T) {
	doc := &Document{
		URI:     "file:///test.yaml",
		Content: "old content",
		Version: 1,
	}

	changes := []protocol.TextDocumentContentChangeEvent{
		{Text: "new content"},
	}

	newDoc := doc.ApplyContentChanges(changes, 2)

	// Original doc should be unchanged (immutable)
	assert.Equal(t, "old content", doc.Content)
	assert.Equal(t, 1, doc.Version)

	// New doc should have changes
	assert.Equal(t, "new content", newDoc.Content)
	assert.Equal(t, 2, newDoc.Version)
}

func TestDocument_ApplyContentChanges_Incremental(t *testing.T) {
	doc := &Document{
		URI:     "file:///test.yaml",
		Content: "line one\nline two\nline three",
		Version: 1,
	}

	// Replace "two" with "TWO"
	changes := []protocol.TextDocumentContentChangeEvent{
		{
			Range: &protocol.Range{
				Start: protocol.Position{Line: 1, Character: 5},
				End:   protocol.Position{Line: 1, Character: 8},
			},
			Text: "TWO",
		},
	}

	newDoc := doc.ApplyContentChanges(changes, 2)

	assert.Equal(t, "line one\nline TWO\nline three", newDoc.Content)
	assert.Equal(t, 2, newDoc.Version)
}

func TestDocument_GetLineContent(t *testing.T) {
	doc := &Document{
		Content: "line 0\nline 1\nline 2",
	}

	assert.Equal(t, "line 0", doc.GetLineContent(0))
	assert.Equal(t, "line 1", doc.GetLineContent(1))
	assert.Equal(t, "line 2", doc.GetLineContent(2))
	assert.Equal(t, "", doc.GetLineContent(3))
	assert.Equal(t, "", doc.GetLineContent(-1))
}

func TestDocument_GetLines(t *testing.T) {
	doc := &Document{
		Content: "a\nb\nc",
	}

	lines := doc.GetLines()
	assert.Equal(t, []string{"a", "b", "c"}, lines)
}

func TestDocument_LineCount(t *testing.T) {
	tests := []struct {
		content  string
		expected int
	}{
		{"", 1}, // Empty string has one empty line
		{"a", 1},
		{"a\nb", 2},
		{"a\nb\nc", 3},
		{"a\nb\n", 3}, // Trailing newline creates empty line
	}

	for _, tt := range tests {
		doc := &Document{Content: tt.content}
		assert.Equal(t, tt.expected, doc.LineCount(), "content: %q", tt.content)
	}
}

func TestApplyTextChange_InvalidRange(t *testing.T) {
	content := "line one\nline two"

	// Start line out of bounds
	result := applyTextChange(content, &protocol.Range{
		Start: protocol.Position{Line: -1, Character: 0},
		End:   protocol.Position{Line: 0, Character: 4},
	}, "NEW")
	assert.Equal(t, content, result)

	// End line out of bounds
	result = applyTextChange(content, &protocol.Range{
		Start: protocol.Position{Line: 0, Character: 0},
		End:   protocol.Position{Line: 100, Character: 0},
	}, "NEW")
	assert.Equal(t, content, result)
}

func TestCalculateOffset(t *testing.T) {
	lines := []string{"abc", "defgh", "ij"}
	// Content: "abc\ndefgh\nij"

	// Line 0, char 0 = offset 0
	assert.Equal(t, 0, calculateOffset(lines, 0, 0))

	// Line 0, char 2 = offset 2
	assert.Equal(t, 2, calculateOffset(lines, 0, 2))

	// Line 1, char 0 = offset 4 (3 chars + 1 newline)
	assert.Equal(t, 4, calculateOffset(lines, 1, 0))

	// Line 1, char 3 = offset 7 (4 + 3)
	assert.Equal(t, 7, calculateOffset(lines, 1, 3))

	// Line 2, char 0 = offset 10 (4 + 5 + 1)
	assert.Equal(t, 10, calculateOffset(lines, 2, 0))
}

func TestDocument_GetWordAtPosition(t *testing.T) {
	doc := &Document{
		URI:     "file:///test.falco.yaml",
		Content: "proc.name = bash\nevt.type = execve",
		Version: 1,
	}

	tests := []struct {
		pos      protocol.Position
		expected string
	}{
		{protocol.Position{Line: 0, Character: 0}, "proc.name"},
		{protocol.Position{Line: 0, Character: 5}, "proc.name"},
		{protocol.Position{Line: 0, Character: 12}, "bash"},
		{protocol.Position{Line: 1, Character: 0}, "evt.type"},
		{protocol.Position{Line: 1, Character: 15}, "execve"},
	}

	for _, tt := range tests {
		got := doc.GetWordAtPosition(tt.pos)
		assert.Equal(t, tt.expected, got, "at position %+v", tt.pos)
	}
}

func TestDocument_GetWordAtPosition_InvalidPosition(t *testing.T) {
	doc := &Document{
		URI:     "file:///test.yaml",
		Content: "hello world",
		Version: 1,
	}

	// Invalid line
	assert.Equal(t, "", doc.GetWordAtPosition(protocol.Position{Line: -1, Character: 0}))
	assert.Equal(t, "", doc.GetWordAtPosition(protocol.Position{Line: 100, Character: 0}))

	// Invalid character
	assert.Equal(t, "", doc.GetWordAtPosition(protocol.Position{Line: 0, Character: -1}))
	assert.Equal(t, "", doc.GetWordAtPosition(protocol.Position{Line: 0, Character: 100}))
}

func TestNewDocument(t *testing.T) {
	doc := NewDocument("file:///test.yaml", "line one\nline two", 1)

	assert.Equal(t, "file:///test.yaml", doc.URI)
	assert.Equal(t, "line one\nline two", doc.Content)
	assert.Equal(t, 1, doc.Version)
	assert.NotNil(t, doc.linesCache)
	assert.Len(t, doc.linesCache, 2)
}

func TestDocument_WithContent(t *testing.T) {
	doc := NewDocument("file:///test.yaml", "old content", 1)
	newDoc := doc.WithContent("new content", 2)

	// Original unchanged
	assert.Equal(t, "old content", doc.Content)
	assert.Equal(t, 1, doc.Version)

	// New doc has changes
	assert.Equal(t, "new content", newDoc.Content)
	assert.Equal(t, 2, newDoc.Version)
	assert.Equal(t, doc.URI, newDoc.URI)
}

func TestDocument_WithResult(t *testing.T) {
	doc := NewDocument("file:///test.yaml", "content", 1)
	result := &parser.ParseResult{}
	newDoc := doc.WithResult(result)

	assert.Nil(t, doc.Result)
	assert.Equal(t, result, newDoc.Result)
	assert.Equal(t, doc.Content, newDoc.Content)
}

func TestDocument_WithSymbols(t *testing.T) {
	doc := NewDocument("file:///test.yaml", "content", 1)
	symbols := &analyzer.SymbolTable{
		Macros: make(map[string]*analyzer.MacroSymbol),
	}
	newDoc := doc.WithSymbols(symbols)

	assert.Nil(t, doc.Symbols)
	assert.Equal(t, symbols, newDoc.Symbols)
	assert.Equal(t, doc.Content, newDoc.Content)
}

func TestStore_SetUnchecked(t *testing.T) {
	ds := NewStore()
	doc := &Document{
		URI:     "test.yaml", // No file:// prefix
		Content: "content",
		Version: 1,
	}

	ds.SetUnchecked(doc)
	assert.Equal(t, 1, ds.Count())

	retrieved, ok := ds.Get("test.yaml")
	assert.True(t, ok)
	assert.Equal(t, doc.Content, retrieved.Content)
}

func TestStore_GetAllSymbols(t *testing.T) {
	ds := NewStore()

	// Add document with symbols
	doc1 := &Document{
		URI:     "file:///a.yaml",
		Content: "content",
		Version: 1,
		Symbols: &analyzer.SymbolTable{
			Macros: map[string]*analyzer.MacroSymbol{
				"macro1": {Name: "macro1"},
			},
			Lists: map[string]*analyzer.ListSymbol{
				"list1": {Name: "list1"},
			},
			Rules: map[string]*analyzer.RuleSymbol{
				"rule1": {Name: "rule1"},
			},
		},
	}
	_ = ds.Set(doc1)

	// Add document without symbols
	doc2 := &Document{
		URI:     "file:///b.yaml",
		Content: "content",
		Version: 1,
	}
	_ = ds.Set(doc2)

	// Add another document with symbols
	doc3 := &Document{
		URI:     "file:///c.yaml",
		Content: "content",
		Version: 1,
		Symbols: &analyzer.SymbolTable{
			Macros: map[string]*analyzer.MacroSymbol{
				"macro2": {Name: "macro2"},
			},
			Lists: map[string]*analyzer.ListSymbol{},
			Rules: map[string]*analyzer.RuleSymbol{},
		},
	}
	_ = ds.Set(doc3)

	allSymbols := ds.GetAllSymbols()
	assert.Len(t, allSymbols.Macros, 2)
	assert.Len(t, allSymbols.Lists, 1)
	assert.Len(t, allSymbols.Rules, 1)
}

func TestNormalizeURI(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// Already a URI
		{"file:///path/to/file.yaml", "file:///path/to/file.yaml"},
		{"untitled:Untitled-1", "untitled:Untitled-1"},
		// Unix absolute path
		{"/path/to/file.yaml", "file:///path/to/file.yaml"},
		// Windows absolute path
		{"C:\\path\\to\\file.yaml", "file:///C:/path/to/file.yaml"},
		{"D:/path/to/file.yaml", "file:///D:/path/to/file.yaml"},
		// Relative path
		{"test.yaml", "test.yaml"},
		{"./test.yaml", "./test.yaml"},
	}

	for _, tt := range tests {
		got := NormalizeURI(tt.input)
		assert.Equal(t, tt.expected, got, "NormalizeURI(%q)", tt.input)
	}
}

func TestGetWordRangeAtPosition(t *testing.T) {
	tests := []struct {
		line      string
		character int
		expStart  int
		expEnd    int
	}{
		{"hello world", 0, 0, 5},
		{"hello world", 3, 0, 5},
		{"hello world", 6, 6, 11},
		{"  indented", 5, 2, 10},
		{"", 0, 0, 0},
		{"hello", -5, 0, 5},  // Negative character clamped
		{"hello", 100, 0, 5}, // Beyond end clamped
	}

	for _, tt := range tests {
		got := GetWordRangeAtPosition(tt.line, tt.character)
		assert.Equal(t, tt.expStart, got.Start, "line %q, char %d start", tt.line, tt.character)
		assert.Equal(t, tt.expEnd, got.End, "line %q, char %d end", tt.line, tt.character)
	}
}

func TestDocument_ApplyContentChanges_MultipleChanges(t *testing.T) {
	doc := &Document{
		URI:     "file:///test.yaml",
		Content: "aaa bbb ccc",
		Version: 1,
	}

	changes := []protocol.TextDocumentContentChangeEvent{
		{
			Range: &protocol.Range{
				Start: protocol.Position{Line: 0, Character: 0},
				End:   protocol.Position{Line: 0, Character: 3},
			},
			Text: "AAA",
		},
		{
			Range: &protocol.Range{
				Start: protocol.Position{Line: 0, Character: 8},
				End:   protocol.Position{Line: 0, Character: 11},
			},
			Text: "CCC",
		},
	}

	newDoc := doc.ApplyContentChanges(changes, 2)
	assert.Equal(t, "AAA bbb CCC", newDoc.Content)
}

func TestApplyTextChange_StartAfterEnd(t *testing.T) {
	content := "hello world"

	// Start offset > end offset should be handled
	result := applyTextChange(content, &protocol.Range{
		Start: protocol.Position{Line: 0, Character: 10},
		End:   protocol.Position{Line: 0, Character: 5},
	}, "NEW")

	// Should handle gracefully
	assert.NotEmpty(t, result)
}
