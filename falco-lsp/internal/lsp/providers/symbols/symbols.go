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

package symbols

import (
	"strings"

	"github.com/c2ndev/falco-lsp/internal/config"
	"github.com/c2ndev/falco-lsp/internal/lsp/document"
	"github.com/c2ndev/falco-lsp/internal/lsp/protocol"
	"github.com/c2ndev/falco-lsp/internal/schema"
	"github.com/c2ndev/falco-lsp/internal/utils"
)

// Provider handles document symbol requests.
type Provider struct {
	documents *document.Store
}

// New creates a new symbol provider.
func New(docs *document.Store) *Provider {
	return &Provider{
		documents: docs,
	}
}

// GetDocumentSymbols returns all symbols in a document.
func (p *Provider) GetDocumentSymbols(doc *document.Document) []protocol.DocumentSymbol {
	if doc == nil {
		return nil
	}

	// Use document-specific symbols for outline view
	symbols := doc.Symbols
	if symbols == nil {
		return nil
	}

	lines := doc.GetLines()
	var result []protocol.DocumentSymbol

	// Add rules
	for name, rule := range symbols.Rules {
		if rule.File != doc.URI && !utils.MatchesURI(rule.File, doc.URI) {
			continue
		}

		detail := ""
		if rule.Source != "" {
			detail = "source: " + rule.Source
		}

		// Calculate actual range from document content
		lineIdx, lineContent, lineLen := protocol.GetLineInfo(lines, rule.Line)

		// Find the actual position of the name in the line
		nameStart, nameEnd := findNameInLine(lineContent, name, "rule:")

		sym := protocol.DocumentSymbol{
			Name:   name,
			Detail: detail,
			Kind:   protocol.SymbolKindClass, // Rules are like classes
			Range: protocol.Range{
				Start: protocol.Position{Line: lineIdx, Character: 0},
				End:   protocol.Position{Line: lineIdx, Character: lineLen},
			},
			SelectionRange: protocol.Range{
				Start: protocol.Position{Line: lineIdx, Character: nameStart},
				End:   protocol.Position{Line: lineIdx, Character: nameEnd},
			},
		}

		// Add rule properties as children if we can find them
		sym.Children = p.findRuleChildren(lines, lineIdx)

		result = append(result, sym)
	}

	// Add macros
	for name, macro := range symbols.Macros {
		if macro.File != doc.URI && !utils.MatchesURI(macro.File, doc.URI) {
			continue
		}

		lineIdx, lineContent, lineLen := protocol.GetLineInfo(lines, macro.Line)

		nameStart, nameEnd := findNameInLine(lineContent, name, "macro:")

		sym := protocol.DocumentSymbol{
			Name:   name,
			Detail: schema.BlockMacro.String(),
			Kind:   protocol.SymbolKindFunction, // Macros are like functions
			Range: protocol.Range{
				Start: protocol.Position{Line: lineIdx, Character: 0},
				End:   protocol.Position{Line: lineIdx, Character: lineLen},
			},
			SelectionRange: protocol.Range{
				Start: protocol.Position{Line: lineIdx, Character: nameStart},
				End:   protocol.Position{Line: lineIdx, Character: nameEnd},
			},
		}
		result = append(result, sym)
	}

	// Add lists
	for name, list := range symbols.Lists {
		if list.File != doc.URI && !utils.MatchesURI(list.File, doc.URI) {
			continue
		}

		detail := formatListDetail(list.Items)
		lineIdx, lineContent, lineLen := protocol.GetLineInfo(lines, list.Line)

		nameStart, nameEnd := findNameInLine(lineContent, name, "list:")

		sym := protocol.DocumentSymbol{
			Name:   name,
			Detail: detail,
			Kind:   protocol.SymbolKindArray, // Lists are arrays
			Range: protocol.Range{
				Start: protocol.Position{Line: lineIdx, Character: 0},
				End:   protocol.Position{Line: lineIdx, Character: lineLen},
			},
			SelectionRange: protocol.Range{
				Start: protocol.Position{Line: lineIdx, Character: nameStart},
				End:   protocol.Position{Line: lineIdx, Character: nameEnd},
			},
		}
		result = append(result, sym)
	}

	return result
}

// findRuleChildren finds child properties of a rule (condition, output, etc.)
func (p *Provider) findRuleChildren(lines []string, ruleLineIdx int) []protocol.DocumentSymbol {
	var children []protocol.DocumentSymbol

	// Scan subsequent lines for properties until we hit the next top-level item
	for i := ruleLineIdx + 1; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		// Stop at next top-level item (starts with "- ")
		if strings.HasPrefix(trimmed, config.YAMLListItemPrefix) {
			break
		}

		// Skip empty lines
		if trimmed == "" {
			continue
		}

		// Look for property definitions
		for _, prop := range childProperties {
			if strings.HasPrefix(trimmed, prop.prefix) {
				if sym := newPropertySymbol(line, i, prop.name); sym != nil {
					children = append(children, *sym)
				}
				break
			}
		}
	}

	return children
}
