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

package hover

import (
	"fmt"

	"github.com/c2ndev/falco-lsp/internal/fields"
	"github.com/c2ndev/falco-lsp/internal/lsp/document"
	"github.com/c2ndev/falco-lsp/internal/lsp/protocol"
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
	if doc == nil {
		return nil
	}

	word := doc.GetWordAtPosition(params.Position)
	if word == "" {
		return nil
	}

	// Check if it's a Falco field
	if field := fields.GetField(word); field != nil {
		content := fmt.Sprintf("**%s** (%s)\n\n%s", field.Name, field.Type, field.Description)
		if field.IsDynamic {
			content += "\n\n*This field accepts an argument*"
		}
		return &protocol.Hover{
			Contents: protocol.MarkupContent{
				Kind:  protocol.MarkupKindMarkdown,
				Value: content,
			},
		}
	}

	// Check if it's a user-defined macro
	symbols := p.documents.GetAllSymbols()
	if symbols != nil {
		if macro, ok := symbols.Macros[word]; ok {
			return &protocol.Hover{
				Contents: protocol.MarkupContent{
					Kind:  protocol.MarkupKindMarkdown,
					Value: fmt.Sprintf("**Macro: %s**\n\n```\n%s\n```\n\nDefined in: %s", word, macro.Condition, macro.File),
				},
			}
		}

		// Check if it's a user-defined list
		if list, ok := symbols.Lists[word]; ok {
			itemsPreview := ""
			if len(list.Items) > 0 {
				items := list.Items
				if len(items) > 10 {
					items = items[:10]
					itemsPreview = fmt.Sprintf("%v... (and %d more)", items, len(list.Items)-10)
				} else {
					itemsPreview = fmt.Sprintf("%v", items)
				}
			}
			return &protocol.Hover{
				Contents: protocol.MarkupContent{
					Kind:  protocol.MarkupKindMarkdown,
					Value: fmt.Sprintf("**List: %s**\n\nItems: %s\n\nDefined in: %s", word, itemsPreview, list.File),
				},
			}
		}

		// Check if it's a user-defined rule
		if rule, ok := symbols.Rules[word]; ok {
			return &protocol.Hover{
				Contents: protocol.MarkupContent{
					Kind:  protocol.MarkupKindMarkdown,
					Value: fmt.Sprintf("**Rule: %s**\n\nSource: %s\n\nDefined in: %s", word, rule.Source, rule.File),
				},
			}
		}
	}

	return nil
}
