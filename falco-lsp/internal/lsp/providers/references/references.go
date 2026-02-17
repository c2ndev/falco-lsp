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

package references

import (
	"github.com/falcosecurity/falco-lsp/internal/config"
	"github.com/falcosecurity/falco-lsp/internal/lsp/document"
	"github.com/falcosecurity/falco-lsp/internal/lsp/protocol"
	"github.com/falcosecurity/falco-lsp/internal/lsp/providers"
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
	// Use shared helper to get word and symbols at position
	lookup := providers.GetSymbolAtPosition(doc, p.documents, params.Position)
	if lookup == nil {
		return nil
	}

	word := lookup.Word
	symbols := lookup.Symbols

	var locations []protocol.Location

	// Check if word is a macro
	if macro, ok := symbols.Macros[word]; ok {
		if params.Context.IncludeDeclaration {
			loc := protocol.NewSymbolLocation(document.NormalizeURI(macro.File), macro.Line, config.OffsetMacroName, len(word))
			locations = append(locations, loc)
		}
		locations = append(locations, p.findMacroReferences(word)...)
	}

	// Check if word is a list
	if list, ok := symbols.Lists[word]; ok {
		if params.Context.IncludeDeclaration {
			loc := protocol.NewSymbolLocation(document.NormalizeURI(list.File), list.Line, config.OffsetListName, len(word))
			locations = append(locations, loc)
		}
		locations = append(locations, p.findListReferences(word)...)
	}

	// Check if word is a rule
	if rule, ok := symbols.Rules[word]; ok {
		if params.Context.IncludeDeclaration {
			loc := protocol.NewSymbolLocation(document.NormalizeURI(rule.File), rule.Line, config.OffsetRuleName, len(word))
			locations = append(locations, loc)
		}
	}

	return locations
}

// findMacroReferences finds all references to a macro in conditions.
func (p *Provider) findMacroReferences(macroName string) []protocol.Location {
	return p.findSymbolReferences(macroName, true)
}

// findListReferences finds all references to a list in conditions.
func (p *Provider) findListReferences(listName string) []protocol.Location {
	return p.findSymbolReferences(listName, false)
}

// findSymbolReferences searches all conditions for references to the given symbol name.
// When skipSelfInMacros is true, the macro with a matching name is excluded (for macro self-references).
func (p *Provider) findSymbolReferences(symbolName string, skipSelfInMacros bool) []protocol.Location {
	var locations []protocol.Location
	symbols := p.documents.GetAllSymbols()
	if symbols == nil {
		return locations
	}

	for _, rule := range symbols.Rules {
		refs := findWordInCondition(rule.Condition, symbolName, rule.File, rule.Line)
		locations = append(locations, refs...)
	}

	for name, macro := range symbols.Macros {
		if skipSelfInMacros && name == symbolName {
			continue
		}
		refs := findWordInCondition(macro.Condition, symbolName, macro.File, macro.Line)
		locations = append(locations, refs...)
	}

	return locations
}
