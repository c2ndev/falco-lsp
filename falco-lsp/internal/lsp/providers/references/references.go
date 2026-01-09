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

package references

import (
	"strings"

	"github.com/c2ndev/falco-lsp/internal/ast"
	"github.com/c2ndev/falco-lsp/internal/condition"
	"github.com/c2ndev/falco-lsp/internal/lsp/document"
	"github.com/c2ndev/falco-lsp/internal/lsp/protocol"
	"github.com/c2ndev/falco-lsp/internal/schema"
	"github.com/c2ndev/falco-lsp/internal/utils"
)

// YAML key offsets - these are the character positions after "- key: " patterns.
const (
	// offsetMacroName is the character offset for macro names after "- macro: ".
	offsetMacroName = 9
	// offsetListName is the character offset for list names after "- list: ".
	offsetListName = 8
	// offsetRuleName is the character offset for rule names after "- rule: ".
	offsetRuleName = 8
)

// Provider handles find references requests.
type Provider struct {
	documents *document.Store
}

// New creates a new references provider.
func New(docs *document.Store) *Provider {
	return &Provider{
		documents: docs,
	}
}

// GetReferences returns all references to the symbol at the given position.
func (p *Provider) GetReferences(doc *document.Document, params protocol.ReferenceParams) []protocol.Location {
	if doc == nil {
		return nil
	}

	word := doc.GetWordAtPosition(params.Position)
	if word == "" {
		return nil
	}

	symbols := p.documents.GetAllSymbols()
	if symbols == nil {
		return nil
	}

	var locations []protocol.Location

	// Check if word is a macro
	if macro, ok := symbols.Macros[word]; ok {
		// Include declaration if requested
		if params.Context.IncludeDeclaration {
			lineIdx := macro.Line - 1
			if lineIdx < 0 {
				lineIdx = 0
			}
			locations = append(locations, protocol.Location{
				URI: document.NormalizeURI(macro.File),
				Range: protocol.Range{
					Start: protocol.Position{Line: lineIdx, Character: offsetMacroName},
					End:   protocol.Position{Line: lineIdx, Character: offsetMacroName + len(word)},
				},
			})
		}

		// Find all usages in rules and other macros
		locations = append(locations, p.findMacroReferences(word)...)
	}

	// Check if word is a list
	if list, ok := symbols.Lists[word]; ok {
		// Include declaration if requested
		if params.Context.IncludeDeclaration {
			lineIdx := list.Line - 1
			if lineIdx < 0 {
				lineIdx = 0
			}
			locations = append(locations, protocol.Location{
				URI: document.NormalizeURI(list.File),
				Range: protocol.Range{
					Start: protocol.Position{Line: lineIdx, Character: offsetListName},
					End:   protocol.Position{Line: lineIdx, Character: offsetListName + len(word)},
				},
			})
		}

		// Find all usages
		locations = append(locations, p.findListReferences(word)...)
	}

	// Check if word is a rule
	if rule, ok := symbols.Rules[word]; ok {
		// Include declaration if requested
		if params.Context.IncludeDeclaration {
			lineIdx := rule.Line - 1
			if lineIdx < 0 {
				lineIdx = 0
			}
			locations = append(locations, protocol.Location{
				URI: document.NormalizeURI(rule.File),
				Range: protocol.Range{
					Start: protocol.Position{Line: lineIdx, Character: offsetRuleName},
					End:   protocol.Position{Line: lineIdx, Character: offsetRuleName + len(word)},
				},
			})
		}
	}

	return locations
}

// findMacroReferences finds all references to a macro in conditions.
func (p *Provider) findMacroReferences(macroName string) []protocol.Location {
	var locations []protocol.Location
	symbols := p.documents.GetAllSymbols()
	if symbols == nil {
		return locations
	}

	// Search in rules
	for _, rule := range symbols.Rules {
		refs := findWordInCondition(rule.Condition, macroName, rule.File, rule.Line)
		locations = append(locations, refs...)
	}

	// Search in macros
	for name, macro := range symbols.Macros {
		if name == macroName {
			continue // Skip the definition itself
		}
		refs := findWordInCondition(macro.Condition, macroName, macro.File, macro.Line)
		locations = append(locations, refs...)
	}

	return locations
}

// findListReferences finds all references to a list in conditions.
func (p *Provider) findListReferences(listName string) []protocol.Location {
	var locations []protocol.Location
	symbols := p.documents.GetAllSymbols()
	if symbols == nil {
		return locations
	}

	// Search in rules
	for _, rule := range symbols.Rules {
		refs := findWordInCondition(rule.Condition, listName, rule.File, rule.Line)
		locations = append(locations, refs...)
	}

	// Search in macros
	for _, macro := range symbols.Macros {
		refs := findWordInCondition(macro.Condition, listName, macro.File, macro.Line)
		locations = append(locations, refs...)
	}

	return locations
}

// findWordInCondition finds occurrences of a word in a condition string using AST parsing.
// This provides precise positions and avoids false positives from substring matches.
func findWordInCondition(cond, word, file string, baseLine int) []protocol.Location {
	var locations []protocol.Location

	if cond == "" {
		return locations
	}

	// Parse the condition into an AST
	parseResult := condition.Parse(cond)
	if parseResult == nil || parseResult.Expression == nil {
		// Fallback to text-based search if parsing fails
		return findWordInConditionText(cond, word, file, baseLine)
	}

	// Walk the AST to find macro and list references
	ast.Walk(parseResult.Expression, func(expr ast.Expression) bool {
		switch e := expr.(type) {
		case *ast.MacroRef:
			if e.Name == word {
				locations = append(locations, protocol.Location{
					URI: document.NormalizeURI(file),
					Range: protocol.Range{
						Start: protocol.Position{
							Line:      utils.SafeLine(baseLine + e.Range.Start.Line - 1), // AST lines are 1-based
							Character: e.Range.Start.Column,
						},
						End: protocol.Position{
							Line:      utils.SafeLine(baseLine + e.Range.End.Line - 1),
							Character: e.Range.End.Column,
						},
					},
				})
			}
		case *ast.ListRef:
			if e.Name == word {
				locations = append(locations, protocol.Location{
					URI: document.NormalizeURI(file),
					Range: protocol.Range{
						Start: protocol.Position{
							Line:      utils.SafeLine(baseLine + e.Range.Start.Line - 1),
							Character: e.Range.Start.Column,
						},
						End: protocol.Position{
							Line:      utils.SafeLine(baseLine + e.Range.End.Line - 1),
							Character: e.Range.End.Column,
						},
					},
				})
			}
		}
		return true // Continue walking
	})

	return locations
}

// findWordInConditionText is the fallback text-based search when AST parsing fails.
func findWordInConditionText(cond, word, file string, baseLine int) []protocol.Location {
	var locations []protocol.Location

	// Simple word boundary search
	// Look for the word surrounded by non-word characters
	idx := 0
	for {
		pos := strings.Index(cond[idx:], word)
		if pos == -1 {
			break
		}

		actualPos := idx + pos

		// Check word boundaries
		isWordStart := actualPos == 0 || !schema.IsIdentifierCharByte(cond[actualPos-1])
		isWordEnd := actualPos+len(word) >= len(cond) || !schema.IsIdentifierCharByte(cond[actualPos+len(word)])

		if isWordStart && isWordEnd {
			// Calculate line offset within condition (conditions can be multiline)
			lineOffset := 0
			charOffset := actualPos
			for i := 0; i < actualPos; i++ {
				if cond[i] == '\n' {
					lineOffset++
					charOffset = actualPos - i - 1
				}
			}

			locations = append(locations, protocol.Location{
				URI: document.NormalizeURI(file),
				Range: protocol.Range{
					Start: protocol.Position{Line: baseLine + lineOffset, Character: charOffset},
					End:   protocol.Position{Line: baseLine + lineOffset, Character: charOffset + len(word)},
				},
			})
		}

		idx = actualPos + 1
	}

	return locations
}
