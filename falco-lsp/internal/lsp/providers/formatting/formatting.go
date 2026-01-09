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

package formatting

import (
	"strings"

	"github.com/c2ndev/falco-lsp/internal/formatter"
	"github.com/c2ndev/falco-lsp/internal/lsp/document"
	"github.com/c2ndev/falco-lsp/internal/lsp/protocol"
)

// Provider handles document formatting requests.
type Provider struct {
	documents      *document.Store
	defaultTabSize int
}

// New creates a new formatting provider.
func New(docs *document.Store, defaultTabSize int) *Provider {
	if defaultTabSize <= 0 {
		defaultTabSize = 2 // default
	}
	return &Provider{
		documents:      docs,
		defaultTabSize: defaultTabSize,
	}
}

// Format formats a document and returns the text edits.
func (p *Provider) Format(doc *document.Document, options protocol.FormattingOptions) []protocol.TextEdit {
	if doc == nil || doc.Content == "" {
		return nil
	}

	formatted := p.formatYAML(doc.Content, options)
	if formatted == doc.Content {
		return nil // No changes needed
	}

	// Return a single edit that replaces the entire document
	lines := doc.GetLines()
	lastLine := len(lines) - 1
	lastChar := 0
	if lastLine >= 0 && lines[lastLine] != "" {
		lastChar = len(lines[lastLine])
	}

	return []protocol.TextEdit{
		{
			Range: protocol.Range{
				Start: protocol.Position{Line: 0, Character: 0},
				End:   protocol.Position{Line: lastLine, Character: lastChar},
			},
			NewText: formatted,
		},
	}
}

// formatYAML formats Falco YAML rules using the centralized formatter.
func (p *Provider) formatYAML(content string, options protocol.FormattingOptions) string {
	// Use client's TabSize if provided, otherwise use default
	tabSize := options.TabSize
	if tabSize <= 0 {
		tabSize = p.defaultTabSize
	}

	// Convert LSP options to formatter options
	opts := formatter.Options{
		TabSize:                tabSize,
		InsertSpaces:           options.InsertSpaces,
		TrimTrailingWhitespace: options.TrimTrailingWhitespace,
		InsertFinalNewline:     options.InsertFinalNewline,
		NormalizeBlankLines:    true, // Always normalize blank lines for LSP
	}

	return formatter.Format(content, opts)
}

// formatLine formats a single line.
func (p *Provider) formatLine(line, indent string, options protocol.FormattingOptions) string {
	// Trim trailing whitespace
	if options.TrimTrailingWhitespace {
		line = strings.TrimRight(line, " \t")
	}

	// Fix indentation for common patterns
	trimmed := strings.TrimLeft(line, " \t")
	if trimmed == "" {
		return ""
	}

	// Calculate current indentation level
	currentIndent := len(line) - len(trimmed)

	// Normalize indentation based on content
	switch {
	case strings.HasPrefix(trimmed, "- "):
		// Top-level list item (rule, macro, list)
		return trimmed
	case strings.HasPrefix(trimmed, "#"):
		// Comment - preserve indentation
		return line
	case p.isPropertyLine(trimmed):
		// Property within an item - should be indented
		expectedIndent := indent
		if currentIndent == 0 {
			return expectedIndent + trimmed
		}
		// Normalize to standard indent
		return expectedIndent + trimmed
	default:
		return line
	}
}

// isPropertyLine returns true if the line is a property definition.
func (p *Provider) isPropertyLine(line string) bool {
	// Common Falco properties
	properties := []string{
		"condition:", "desc:", "output:", "priority:", "source:",
		"enabled:", "tags:", "append:", "override:", "items:",
		"exceptions:", "warn_evttypes:", "skip-if-unknown-filter:",
	}

	for _, prop := range properties {
		if strings.HasPrefix(line, prop) {
			return true
		}
	}

	return false
}

// FormatRange formats a range of a document and returns the text edits.
func (p *Provider) FormatRange(
	doc *document.Document,
	params protocol.DocumentRangeFormattingParams,
) []protocol.TextEdit {
	if doc == nil || doc.Content == "" {
		return nil
	}

	lines := doc.GetLines()
	startLine := params.Range.Start.Line
	endLine := params.Range.End.Line

	if startLine < 0 || startLine >= len(lines) {
		return nil
	}
	if endLine < 0 || endLine >= len(lines) {
		endLine = len(lines) - 1
	}

	indent := "  "
	if params.Options.TabSize > 0 && params.Options.InsertSpaces {
		indent = strings.Repeat(" ", params.Options.TabSize)
	}

	var edits []protocol.TextEdit
	for i := startLine; i <= endLine; i++ {
		original := lines[i]
		formatted := p.formatLine(original, indent, params.Options)
		if formatted != original {
			edits = append(edits, protocol.TextEdit{
				Range: protocol.Range{
					Start: protocol.Position{Line: i, Character: 0},
					End:   protocol.Position{Line: i, Character: len(original)},
				},
				NewText: formatted,
			})
		}
	}

	return edits
}
