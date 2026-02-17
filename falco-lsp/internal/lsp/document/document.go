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

package document

import (
	"errors"
	"net/url"
	"strings"
	"sync"

	"github.com/falcosecurity/falco-lsp/internal/analyzer"
	"github.com/falcosecurity/falco-lsp/internal/lsp/protocol"
	"github.com/falcosecurity/falco-lsp/internal/parser"
	"github.com/falcosecurity/falco-lsp/internal/schema"
)

// Errors for document operations.
var (
	ErrEmptyURI      = errors.New("document URI cannot be empty")
	ErrInvalidURI    = errors.New("document URI is invalid")
	ErrInvalidScheme = errors.New("document URI must have file:// or untitled: scheme")
)

// ValidateURI validates a document URI.
// Returns nil if valid, or an error describing the problem.
func ValidateURI(uri string) error {
	if uri == "" {
		return ErrEmptyURI
	}

	// Parse the URI
	parsed, err := url.Parse(uri)
	if err != nil {
		return ErrInvalidURI
	}

	// Allow file:// and untitled: schemes, or plain paths for testing
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "" && scheme != "file" && scheme != "untitled" {
		return ErrInvalidScheme
	}

	// Check for path traversal attempts in the path
	if strings.Contains(uri, "..") {
		return ErrInvalidURI
	}

	return nil
}

// Document represents an open text document with its state.
// Document is designed to be immutable after creation - create a new Document
// to update content rather than modifying in place.
//
// IMPORTANT: Always use NewDocument() to create Document instances to ensure
// the linesCache is properly initialized. Direct struct literals will not
// have the cache pre-populated.
type Document struct {
	URI        string
	Content    string
	Version    int
	Result     *parser.ParseResult
	Symbols    *analyzer.SymbolTable // Analyzed symbols for this document
	linesCache []string              // Cached lines, pre-populated at creation time
}

// NewDocument creates a new Document with pre-populated linesCache.
// This is the preferred way to create Document instances.
func NewDocument(uri, content string, version int) *Document {
	return &Document{
		URI:        uri,
		Content:    content,
		Version:    version,
		linesCache: strings.Split(content, "\n"),
	}
}

// Store manages open documents with thread-safe access.
type Store struct {
	mu        sync.RWMutex
	documents map[string]*Document
}

// NewStore creates a new document store.
func NewStore() *Store {
	return &Store{
		documents: make(map[string]*Document),
	}
}

// Get retrieves a document by URI.
func (s *Store) Get(uri string) (*Document, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	doc, ok := s.documents[uri]
	return doc, ok
}

// Set stores or updates a document.
// Returns an error if the document URI is invalid.
func (s *Store) Set(doc *Document) error {
	if err := ValidateURI(doc.URI); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.documents[doc.URI] = doc
	return nil
}

// SetUnchecked stores or updates a document without URI validation.
// Use only in tests or when URI is known to be valid.
func (s *Store) SetUnchecked(doc *Document) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.documents[doc.URI] = doc
}

// Delete removes a document.
func (s *Store) Delete(uri string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.documents, uri)
}

// All returns all documents.
func (s *Store) All() []*Document {
	s.mu.RLock()
	defer s.mu.RUnlock()
	docs := make([]*Document, 0, len(s.documents))
	for _, doc := range s.documents {
		docs = append(docs, doc)
	}
	return docs
}

// Count returns the number of open documents.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.documents)
}

// GetAllSymbols returns aggregated symbols from all open documents.
// This is useful for cross-file references (e.g., macros defined in one file used in another).
func (s *Store) GetAllSymbols() *analyzer.SymbolTable {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := &analyzer.SymbolTable{
		Macros: make(map[string]*analyzer.MacroSymbol),
		Lists:  make(map[string]*analyzer.ListSymbol),
		Rules:  make(map[string]*analyzer.RuleSymbol),
	}

	for _, doc := range s.documents {
		if doc.Symbols == nil {
			continue
		}
		for name, macro := range doc.Symbols.Macros {
			result.Macros[name] = macro
		}
		for name, list := range doc.Symbols.Lists {
			result.Lists[name] = list
		}
		for name, rule := range doc.Symbols.Rules {
			result.Rules[name] = rule
		}
	}

	return result
}

// ApplyContentChanges applies incremental or full content changes to a document.
// Returns a new Document with the changes applied (immutable pattern).
func (doc *Document) ApplyContentChanges(changes []protocol.TextDocumentContentChangeEvent, newVersion int) *Document {
	newContent := doc.Content
	for _, change := range changes {
		if change.Range == nil {
			// Full document sync
			newContent = change.Text
		} else {
			// Incremental sync
			newContent = applyTextChange(newContent, change.Range, change.Text)
		}
	}
	// Use NewDocument to ensure linesCache is properly initialized
	return NewDocument(doc.URI, newContent, newVersion)
}

// WithContent returns a new Document with updated content (immutable pattern).
func (doc *Document) WithContent(content string, version int) *Document {
	// Use NewDocument to ensure linesCache is properly initialized
	return NewDocument(doc.URI, content, version)
}

// WithResult returns a new Document with updated parse result (immutable pattern).
func (doc *Document) WithResult(result *parser.ParseResult) *Document {
	return &Document{
		URI:        doc.URI,
		Content:    doc.Content,
		Version:    doc.Version,
		Result:     result,
		Symbols:    doc.Symbols,
		linesCache: doc.linesCache,
	}
}

// WithSymbols returns a new Document with updated symbols (immutable pattern).
func (doc *Document) WithSymbols(symbols *analyzer.SymbolTable) *Document {
	return &Document{
		URI:        doc.URI,
		Content:    doc.Content,
		Version:    doc.Version,
		Result:     doc.Result,
		Symbols:    symbols,
		linesCache: doc.linesCache,
	}
}

// applyTextChange applies an incremental text change to document content.
func applyTextChange(content string, r *protocol.Range, newText string) string {
	lines := strings.Split(content, "\n")

	// Validate range bounds
	if r.Start.Line < 0 || r.Start.Line >= len(lines) {
		return content
	}
	if r.End.Line < 0 || r.End.Line >= len(lines) {
		return content
	}

	// Calculate byte offsets
	startOffset := calculateOffset(lines, r.Start.Line, r.Start.Character)
	endOffset := calculateOffset(lines, r.End.Line, r.End.Character)

	// Clamp offsets
	if startOffset < 0 {
		startOffset = 0
	}
	if endOffset > len(content) {
		endOffset = len(content)
	}
	if startOffset > endOffset {
		startOffset = endOffset
	}

	return content[:startOffset] + newText + content[endOffset:]
}

// calculateOffset calculates the byte offset for a given line and character.
func calculateOffset(lines []string, line, character int) int {
	offset := 0
	for i := 0; i < line && i < len(lines); i++ {
		offset += len(lines[i]) + 1 // +1 for newline
	}
	if line < len(lines) {
		lineLen := len(lines[line])
		if character > lineLen {
			character = lineLen
		}
		offset += character
	}
	return offset
}

// GetLineContent returns the content of a specific line (0-based).
func (doc *Document) GetLineContent(line int) string {
	lines := doc.GetLines()
	if line < 0 || line >= len(lines) {
		return ""
	}
	return lines[line]
}

// GetLines returns all lines of the document.
// The lines are cached at document creation time for thread-safety.
// If the document was created without NewDocument(), falls back to splitting.
func (doc *Document) GetLines() []string {
	if doc.linesCache != nil {
		return doc.linesCache
	}
	// Fallback for documents not created via NewDocument (e.g., tests)
	return strings.Split(doc.Content, "\n")
}

// LineCount returns the number of lines in the document.
func (doc *Document) LineCount() int {
	return len(doc.GetLines())
}

// GetWordAtPosition returns the word at the given position.
func (doc *Document) GetWordAtPosition(pos protocol.Position) string {
	lines := doc.GetLines()
	// Validate line bounds
	if pos.Line < 0 || pos.Line >= len(lines) {
		return ""
	}

	line := lines[pos.Line]
	// Validate character bounds
	if pos.Character < 0 || pos.Character >= len(line) {
		return ""
	}

	// Find word boundaries
	start := pos.Character
	for start > 0 && schema.IsFieldChar(rune(line[start-1])) {
		start--
	}

	end := pos.Character
	for end < len(line) && schema.IsFieldChar(rune(line[end])) {
		end++
	}

	if start >= end {
		return ""
	}
	return line[start:end]
}

// WordRange represents the start and end character positions of a word.
type WordRange struct {
	Start int
	End   int
}

// GetWordRangeAtPosition returns the word range at a position in a line.
func GetWordRangeAtPosition(line string, character int) WordRange {
	runes := []rune(line)

	// Clamp character to valid range
	if character < 0 {
		character = 0
	}
	if character > len(runes) {
		character = len(runes)
	}

	// Find start
	start := character
	for start > 0 && schema.IsWordChar(runes[start-1]) {
		start--
	}

	// Find end
	end := character
	for end < len(runes) && schema.IsWordChar(runes[end]) {
		end++
	}

	return WordRange{Start: start, End: end}
}

// NormalizeURI normalizes a file path to a proper file:// URI.
// Handles both Unix (/path/to/file) and Windows (C:\path\to\file) paths.
func NormalizeURI(path string) string {
	// Already a URI
	if strings.HasPrefix(path, "file://") ||
		strings.HasPrefix(path, "untitled:") {
		return path
	}

	// Unix absolute path
	if strings.HasPrefix(path, "/") {
		return "file://" + path
	}

	// Windows absolute path (C:\, D:\, etc.)
	if len(path) >= 3 && path[1] == ':' &&
		(path[2] == '\\' || path[2] == '/') {
		// Convert backslashes to forward slashes
		normalized := strings.ReplaceAll(path, "\\", "/")
		return "file:///" + normalized
	}

	// Relative path or already normalized
	return path
}
