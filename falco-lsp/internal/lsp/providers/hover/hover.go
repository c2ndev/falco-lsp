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

package hover

import (
	"fmt"

	"github.com/falcosecurity/falco-lsp/internal/config"
	"github.com/falcosecurity/falco-lsp/internal/fields"
	"github.com/falcosecurity/falco-lsp/internal/lsp/document"
	"github.com/falcosecurity/falco-lsp/internal/lsp/protocol"
	"github.com/falcosecurity/falco-lsp/internal/lsp/providers"
)

// Provider handles hover requests.
type Provider struct {
	documents *document.Store
}

// New creates a new hover provider.
func New(docs *document.Store) *Provider {
	return &Provider{
		documents: docs,
	}
}

// GetHover returns hover information for the given position.
func (p *Provider) GetHover(doc *document.Document, params protocol.TextDocumentPositionParams) *protocol.Hover {
	// Use shared helper to get word at position
	lookup := providers.GetSymbolAtPosition(doc, p.documents, params.Position)
	if lookup == nil {
		return nil
	}

	// Check if it's a Falco field
	if hover := p.getFieldHover(lookup.Word); hover != nil {
		return hover
	}

	// Check if it's a user-defined symbol
	return p.getSymbolHover(lookup)
}

// getFieldHover returns hover information for a Falco field.
func (p *Provider) getFieldHover(word string) *protocol.Hover {
	field := fields.GetField(word)
	if field == nil {
		return nil
	}

	content := fmt.Sprintf("**%s** (%s)\n\n%s", field.Name, field.Type, field.Description)
	if field.IsDynamic {
		content += "\n\n*This field accepts an argument*"
	}
	return newMarkdownHover(content)
}

// getSymbolHover returns hover information for a user-defined symbol.
func (p *Provider) getSymbolHover(lookup *providers.SymbolLookup) *protocol.Hover {
	word := lookup.Word
	symbols := lookup.Symbols

	// Check macro
	if macro, ok := symbols.Macros[word]; ok {
		content := fmt.Sprintf("**Macro: %s**\n\n```\n%s\n```\n\nDefined in: %s", word, macro.Condition, macro.File)
		return newMarkdownHover(content)
	}

	// Check list
	if list, ok := symbols.Lists[word]; ok {
		itemsPreview := formatListPreview(list.Items)
		content := fmt.Sprintf("**List: %s**\n\nItems: %s\n\nDefined in: %s", word, itemsPreview, list.File)
		return newMarkdownHover(content)
	}

	// Check rule
	if rule, ok := symbols.Rules[word]; ok {
		content := fmt.Sprintf("**Rule: %s**\n\nSource: %s\n\nDefined in: %s", word, rule.Source, rule.File)
		return newMarkdownHover(content)
	}

	return nil
}

// formatListPreview formats a list of items for hover display.
func formatListPreview(items []string) string {
	if len(items) == 0 {
		return ""
	}

	maxItems := config.ListPreviewItemsHover
	if len(items) > maxItems {
		return fmt.Sprintf("%v... (and %d more)", items[:maxItems], len(items)-maxItems)
	}
	return fmt.Sprintf("%v", items)
}

// newMarkdownHover creates a Hover with markdown content.
func newMarkdownHover(content string) *protocol.Hover {
	return &protocol.Hover{
		Contents: protocol.MarkupContent{
			Kind:  protocol.MarkupKindMarkdown,
			Value: content,
		},
	}
}
