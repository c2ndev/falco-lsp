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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/c2ndev/falco-lsp/internal/analyzer"
	"github.com/c2ndev/falco-lsp/internal/lsp/document"
	"github.com/c2ndev/falco-lsp/internal/lsp/protocol"
)

func TestGetSymbolAtPosition(t *testing.T) {
	tests := []struct {
		name     string
		setupDoc func(*document.Store) *document.Document
		pos      protocol.Position
		wantNil  bool
		wantWord string
	}{
		{
			name: "nil document returns nil",
			setupDoc: func(_ *document.Store) *document.Document {
				return nil
			},
			pos:     protocol.Position{Line: 0, Character: 0},
			wantNil: true,
		},
		{
			name: "empty word at position returns nil",
			setupDoc: func(store *document.Store) *document.Document {
				doc := document.NewDocument("test.yaml", "   ", 1)
				docWithSymbols := doc.WithSymbols(&analyzer.SymbolTable{
					Macros: make(map[string]*analyzer.MacroSymbol),
					Lists:  make(map[string]*analyzer.ListSymbol),
					Rules:  make(map[string]*analyzer.RuleSymbol),
				})
				store.SetUnchecked(docWithSymbols)
				return docWithSymbols
			},
			pos:     protocol.Position{Line: 0, Character: 1},
			wantNil: true,
		},
		{
			name: "valid word with symbols returns lookup",
			setupDoc: func(store *document.Store) *document.Document {
				doc := document.NewDocument("test.yaml", "my_macro", 1)
				docWithSymbols := doc.WithSymbols(&analyzer.SymbolTable{
					Macros: map[string]*analyzer.MacroSymbol{
						"my_macro": {Name: "my_macro"},
					},
					Lists: make(map[string]*analyzer.ListSymbol),
					Rules: make(map[string]*analyzer.RuleSymbol),
				})
				store.SetUnchecked(docWithSymbols)
				return docWithSymbols
			},
			pos:      protocol.Position{Line: 0, Character: 3},
			wantNil:  false,
			wantWord: "my_macro",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := document.NewStore()
			doc := tt.setupDoc(store)

			result := GetSymbolAtPosition(doc, store, tt.pos)

			if tt.wantNil {
				assert.Nil(t, result, "Expected nil result")
			} else {
				require.NotNil(t, result, "Expected non-nil result")
				assert.Equal(t, tt.wantWord, result.Word, "Word mismatch")
				assert.NotNil(t, result.Symbols, "Symbols should not be nil")
			}
		})
	}
}

func TestGetSymbolAtPosition_NilSymbols(t *testing.T) {
	store := document.NewStore()
	doc := document.NewDocument("test.yaml", "my_macro", 1)
	// Don't set symbols on the document - store.GetAllSymbols() will return empty table
	store.SetUnchecked(doc)

	result := GetSymbolAtPosition(doc, store, protocol.Position{Line: 0, Character: 3})
	// GetAllSymbols returns empty table (not nil) when documents have no symbols
	// So the lookup should succeed but with empty symbols
	require.NotNil(t, result, "Expected non-nil result even with empty symbols")
	assert.Equal(t, "my_macro", result.Word, "Word should be extracted")
}
