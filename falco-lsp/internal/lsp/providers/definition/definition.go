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
	"github.com/c2ndev/falco-lsp/internal/lsp/providers"
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
	// Use shared helper to get word and symbols at position
	lookup := providers.GetSymbolAtPosition(doc, p.documents, params.Position)
	if lookup == nil {
		return nil
	}

	word := lookup.Word
	symbols := lookup.Symbols

	// Check macros
	if macro, ok := symbols.Macros[word]; ok {
		return protocol.NewSymbolLocationPtr(document.NormalizeURI(macro.File), macro.Line, len(word))
	}

	// Check lists
	if list, ok := symbols.Lists[word]; ok {
		return protocol.NewSymbolLocationPtr(document.NormalizeURI(list.File), list.Line, len(word))
	}

	// Check rules
	if rule, ok := symbols.Rules[word]; ok {
		return protocol.NewSymbolLocationPtr(document.NormalizeURI(rule.File), rule.Line, len(word))
	}

	return nil
}
