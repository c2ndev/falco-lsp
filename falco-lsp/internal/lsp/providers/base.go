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

package providers

import (
	"github.com/c2ndev/falco-lsp/internal/analyzer"
	"github.com/c2ndev/falco-lsp/internal/lsp/document"
	"github.com/c2ndev/falco-lsp/internal/lsp/protocol"
)

// SymbolLookup holds the result of looking up a symbol at a cursor position.
type SymbolLookup struct {
	Word    string
	Symbols *analyzer.SymbolTable
}

// GetSymbolAtPosition returns the word and symbols at a given position.
// Returns nil if:
// - doc is nil
// - word at position is empty
// - no symbols are available in the document store
//
// This helper eliminates duplicated lookup patterns across hover, definition, and references providers.
func GetSymbolAtPosition(doc *document.Document, docs *document.Store, pos protocol.Position) *SymbolLookup {
	if doc == nil {
		return nil
	}

	word := doc.GetWordAtPosition(pos)
	if word == "" {
		return nil
	}

	symbols := docs.GetAllSymbols()
	if symbols == nil {
		return nil
	}

	return &SymbolLookup{
		Word:    word,
		Symbols: symbols,
	}
}
