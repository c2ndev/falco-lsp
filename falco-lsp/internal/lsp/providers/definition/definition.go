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

package definition

import (
	"github.com/c2ndev/falco-lsp/internal/lsp/document"
	"github.com/c2ndev/falco-lsp/internal/lsp/protocol"
)

// Provider handles go-to-definition requests.
type Provider struct {
	documents *document.Store
}

// New creates a new definition provider.
func New(docs *document.Store) *Provider {
	return &Provider{
		documents: docs,
	}
}

// GetDefinition returns the location of the definition for the symbol at the given position.
func (p *Provider) GetDefinition(
	doc *document.Document,
	params protocol.TextDocumentPositionParams,
) *protocol.Location {
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

	// Check macros
	if macro, ok := symbols.Macros[word]; ok {
		lineIdx := macro.Line - 1
		if lineIdx < 0 {
			lineIdx = 0
		}
		return &protocol.Location{
			URI: document.NormalizeURI(macro.File),
			Range: protocol.Range{
				Start: protocol.Position{Line: lineIdx, Character: 0},
				End:   protocol.Position{Line: lineIdx, Character: len(word)},
			},
		}
	}

	// Check lists
	if list, ok := symbols.Lists[word]; ok {
		lineIdx := list.Line - 1
		if lineIdx < 0 {
			lineIdx = 0
		}
		return &protocol.Location{
			URI: document.NormalizeURI(list.File),
			Range: protocol.Range{
				Start: protocol.Position{Line: lineIdx, Character: 0},
				End:   protocol.Position{Line: lineIdx, Character: len(word)},
			},
		}
	}

	// Check rules
	if rule, ok := symbols.Rules[word]; ok {
		lineIdx := rule.Line - 1
		if lineIdx < 0 {
			lineIdx = 0
		}
		return &protocol.Location{
			URI: document.NormalizeURI(rule.File),
			Range: protocol.Range{
				Start: protocol.Position{Line: lineIdx, Character: 0},
				End:   protocol.Position{Line: lineIdx, Character: len(word)},
			},
		}
	}

	return nil
}
