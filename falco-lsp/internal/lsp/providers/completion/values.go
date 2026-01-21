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

package completion

import (
	"strings"

	"github.com/c2ndev/falco-lsp/internal/fields"
	"github.com/c2ndev/falco-lsp/internal/lsp/protocol"
	"github.com/c2ndev/falco-lsp/internal/schema"
)

// =============================================================================
// Value Completions - Priority, Source, Boolean
// =============================================================================

func (p *Provider) getPriorityCompletions() []protocol.CompletionItem {
	return newValueCompletions(schema.AllPriorities, schema.PropPriority.String(),
		func(pr schema.PriorityInfo) (string, string) { return pr.Level.String(), pr.Description })
}

func (p *Provider) getSourceCompletions() []protocol.CompletionItem {
	return newValueCompletions(schema.AllSources, schema.PropSource.String(),
		func(s schema.SourceInfo) (string, string) { return s.Type.String(), s.Description })
}

func (p *Provider) getBooleanCompletions() []protocol.CompletionItem {
	return []protocol.CompletionItem{
		{Label: BoolTrue, Kind: protocol.CompletionItemKindValue},
		{Label: BoolFalse, Kind: protocol.CompletionItemKindValue},
	}
}

func (p *Provider) getConditionCompletions(prefix string, cursorAfterWord bool) []protocol.CompletionItem {
	items := make([]protocol.CompletionItem, 0, p.maxCompletionItems)

	// If cursor is after a complete word followed by a space (e.g., "proc.name |"),
	// prioritize operators over fields - user likely wants to type an operator next.
	if cursorAfterWord && isFieldPrefix(prefix) {
		// After a field like "proc.name ", show operators primarily
		items = append(items, newOperatorCompletions(schema.ComparisonOperators, protocol.CompletionItemKindOperator)...)
		items = append(items, newOperatorCompletions(schema.LogicalOperators, protocol.CompletionItemKindKeyword)...)
		return items
	}

	// Add all Falco fields (with optional filtering by prefix)
	items = append(items, newFieldCompletions(fields.GetAllFields(), prefix, false)...)

	// Add operators, macros, lists, and event types (only if no specific field prefix)
	if !isFieldPrefix(prefix) {
		items = append(items, newOperatorCompletions(schema.LogicalOperators, protocol.CompletionItemKindKeyword)...)
		items = append(items, newOperatorCompletions(schema.ComparisonOperators, protocol.CompletionItemKindOperator)...)
		items = append(items, p.getMacroCompletions()...)
		items = append(items, p.getListCompletions()...)
		items = append(items, newEventTypeCompletions(schema.AllEventTypes())...)
	}

	return items
}

func (p *Provider) getOutputCompletions(prefix string) []protocol.CompletionItem {
	return newFieldCompletions(fields.GetAllFields(), prefix, true)
}

func (p *Provider) getTagsCompletions() []protocol.CompletionItem {
	return newValueCompletions(schema.AllTags(), "tag",
		func(t schema.TagInfo) (string, string) { return t.Name, t.Description })
}

func (p *Provider) getListItemCompletions() []protocol.CompletionItem {
	items := p.getListCompletions()

	for _, b := range schema.CommonBinaries {
		items = append(items, protocol.CompletionItem{
			Label:  b,
			Kind:   protocol.CompletionItemKindValue,
			Detail: "common binary",
		})
	}

	return items
}

func (p *Provider) getConditionFieldCompletions() []protocol.CompletionItem {
	return newFieldCompletions(fields.GetAllFields(), "", false)
}

func (p *Provider) getComparisonOperatorCompletions() []protocol.CompletionItem {
	return newOperatorCompletions(schema.ComparisonOperators, protocol.CompletionItemKindOperator)
}

func (p *Provider) getExceptionPropertyCompletions() []protocol.CompletionItem {
	return newPropertyCompletions(schema.ExceptionProperties)
}

func (p *Provider) getPluginVersionCompletions() []protocol.CompletionItem {
	return newPropertyCompletions(schema.PluginVersionProperties)
}

func (p *Provider) getOverridePropertyCompletions() []protocol.CompletionItem {
	return newPropertyCompletionsWithSuffix(schema.OverrideableProperties, ": replace")
}

// =============================================================================
// Block Property Completions - Rule, Macro, List
// =============================================================================

func (p *Provider) getRulePropertyCompletions() []protocol.CompletionItem {
	return newPropertyCompletions(schema.RuleProperties)
}

func (p *Provider) getMacroPropertyCompletions() []protocol.CompletionItem {
	return newPropertyCompletions(schema.MacroProperties)
}

func (p *Provider) getListPropertyCompletions() []protocol.CompletionItem {
	return newPropertyCompletions(schema.ListProperties)
}

// =============================================================================
// Symbol Completions - Macros, Lists
// =============================================================================

func (p *Provider) getMacroCompletions() []protocol.CompletionItem {
	symbols := p.documents.GetAllSymbols()
	if symbols == nil {
		return nil
	}
	return newSymbolCompletions(symbols.Macros, protocol.CompletionItemKindFunction, schema.BlockMacro.String(), macroDocumentation)
}

func (p *Provider) getListCompletions() []protocol.CompletionItem {
	symbols := p.documents.GetAllSymbols()
	if symbols == nil {
		return nil
	}
	return newSymbolCompletions(symbols.Lists, protocol.CompletionItemKindVariable, schema.BlockList.String(), listDocumentation)
}

// =============================================================================
// Top-Level Completions
// =============================================================================

func (p *Provider) getTopLevelCompletions(linePrefix string, position protocol.Position) []protocol.CompletionItem {
	indentation := extractIndentation(linePrefix)
	hasListPrefix := strings.HasPrefix(strings.TrimSpace(linePrefix), "-")
	replaceRange := calculateReplaceRange(linePrefix, position, indentation, hasListPrefix)

	items := make([]protocol.CompletionItem, 0, len(schema.AllSnippets))
	for _, snippet := range schema.AllSnippets {
		items = append(items, snippetToCompletionItem(snippet, replaceRange, indentation, hasListPrefix))
	}

	return items
}
