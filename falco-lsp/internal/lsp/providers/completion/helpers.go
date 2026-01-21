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
	"fmt"
	"strings"

	"github.com/c2ndev/falco-lsp/internal/analyzer"
	"github.com/c2ndev/falco-lsp/internal/config"
	"github.com/c2ndev/falco-lsp/internal/fields"
	"github.com/c2ndev/falco-lsp/internal/lsp/document"
	"github.com/c2ndev/falco-lsp/internal/lsp/protocol"
	"github.com/c2ndev/falco-lsp/internal/schema"
)

// =============================================================================
// Constants
// =============================================================================

// RequiredSuffix is appended to required property completions.
const RequiredSuffix = " (required)"

// Boolean value constants.
const (
	BoolTrue  = "true"
	BoolFalse = "false"
)

// Documentation string constants.
const (
	DocUserDefinedMacro = "User-defined macro"
	DocUserDefinedList  = "User-defined list"
)

// =============================================================================
// Generic Completion Builders
// =============================================================================

// newValueCompletions creates completion items from a slice using a label/doc extractor function.
func newValueCompletions[T any](items []T, detail string, extract func(T) (label, doc string)) []protocol.CompletionItem {
	result := make([]protocol.CompletionItem, 0, len(items))
	for _, item := range items {
		label, doc := extract(item)
		result = append(result, protocol.CompletionItem{
			Label:         label,
			Kind:          protocol.CompletionItemKindValue,
			Detail:        detail,
			Documentation: doc,
		})
	}
	return result
}

// newFieldCompletions creates completion items from field definitions with optional filtering.
// If prefixWithPercent is true, adds "%" prefix to labels (for output context).
func newFieldCompletions(allFields []*fields.Field, filterPrefix string, prefixWithPercent bool) []protocol.CompletionItem {
	items := make([]protocol.CompletionItem, 0, len(allFields))
	matchPrefix := strings.TrimPrefix(filterPrefix, "%")

	for _, f := range allFields {
		if matchPrefix != "" && !strings.HasPrefix(f.Name, matchPrefix) {
			continue
		}
		label := f.Name
		if prefixWithPercent {
			label = "%" + f.Name
		}
		items = append(items, protocol.CompletionItem{
			Label:         label,
			Kind:          protocol.CompletionItemKindField,
			Detail:        f.Type,
			Documentation: f.Description,
			FilterText:    label,
			InsertText:    label,
		})
	}
	return items
}

// newOperatorCompletions creates completion items from operator definitions.
// The kind parameter specifies the completion item kind (e.g., Keyword for logical operators, Operator for comparison operators).
func newOperatorCompletions(ops []schema.OperatorInfo, kind int) []protocol.CompletionItem {
	items := make([]protocol.CompletionItem, 0, len(ops))
	for _, op := range ops {
		items = append(items, protocol.CompletionItem{
			Label:         op.Name,
			Kind:          kind,
			Detail:        op.Category,
			Documentation: op.Description,
		})
	}
	return items
}

// newEventTypeCompletions creates completion items for event types.
func newEventTypeCompletions(events []schema.EventTypeInfo) []protocol.CompletionItem {
	items := make([]protocol.CompletionItem, 0, len(events))
	for _, evt := range events {
		items = append(items, protocol.CompletionItem{
			Label:         evt.Name,
			Kind:          protocol.CompletionItemKindValue,
			Detail:        evt.Category,
			Documentation: evt.Description,
		})
	}
	return items
}

// newPropertyCompletions creates completion items for block properties.
func newPropertyCompletions(props []schema.PropertyInfo) []protocol.CompletionItem {
	return newPropertyCompletionsWithSuffix(props, ": ")
}

// newPropertyCompletionsWithSuffix creates completion items with a custom insert suffix.
func newPropertyCompletionsWithSuffix(props []schema.PropertyInfo, insertSuffix string) []protocol.CompletionItem {
	items := make([]protocol.CompletionItem, 0, len(props))
	for _, prop := range props {
		detail := prop.Description
		if prop.Required {
			detail += RequiredSuffix
		}
		items = append(items, protocol.CompletionItem{
			Label:      prop.Name.String(),
			Kind:       protocol.CompletionItemKindProperty,
			Detail:     detail,
			InsertText: prop.Name.String() + insertSuffix,
		})
	}
	return items
}

// newSinglePropertyCompletion creates a single property completion item.
func newSinglePropertyCompletion(label, detail string) []protocol.CompletionItem {
	return []protocol.CompletionItem{{
		Label:  label,
		Kind:   protocol.CompletionItemKindProperty,
		Detail: detail,
	}}
}

// newSymbolCompletions creates completion items from a map of user-defined symbols.
// The extract function receives the symbol name and value, and returns the documentation string.
func newSymbolCompletions[T any](symbols map[string]T, kind int, detail string, extractDoc func(name string, v T) string) []protocol.CompletionItem {
	items := make([]protocol.CompletionItem, 0, len(symbols))
	for name, sym := range symbols {
		items = append(items, protocol.CompletionItem{
			Label:         name,
			Kind:          kind,
			Detail:        detail,
			Documentation: extractDoc(name, sym),
		})
	}
	return items
}

// macroDocumentation returns the documentation string for a macro symbol.
func macroDocumentation(_ string, m *analyzer.MacroSymbol) string {
	if m.Condition == "" {
		return DocUserDefinedMacro
	}
	return fmt.Sprintf("%s: %s", DocUserDefinedMacro, m.Condition)
}

// listDocumentation returns the documentation string for a list symbol.
func listDocumentation(_ string, l *analyzer.ListSymbol) string {
	if len(l.Items) == 0 {
		return DocUserDefinedList
	}
	previewItems := l.Items
	maxItems := config.ListPreviewItemsCompletion
	if len(previewItems) > maxItems {
		previewItems = previewItems[:maxItems]
	}
	return fmt.Sprintf("%s: [%s...]", DocUserDefinedList, strings.Join(previewItems, ", "))
}

// =============================================================================
// Snippet Helpers
// =============================================================================

// calculateReplaceRange determines the text range to replace when inserting a completion.
// If the user has typed a dash prefix (e.g., "- ru"), replace from the dash.
// Otherwise, replace from the end of indentation.
func calculateReplaceRange(linePrefix string, position protocol.Position, indentation string, hasListPrefix bool) protocol.Range {
	startChar := len(indentation)

	if hasListPrefix {
		if dashIndex := strings.Index(linePrefix, "-"); dashIndex >= 0 {
			startChar = dashIndex
		}
	}

	return protocol.Range{
		Start: protocol.Position{Line: position.Line, Character: startChar},
		End:   position,
	}
}

// snippetToCompletionItem converts a schema.Snippet to a protocol.CompletionItem.
func snippetToCompletionItem(snippet schema.Snippet, replaceRange protocol.Range, indentation string, hasListPrefix bool) protocol.CompletionItem {
	filterText := snippet.Label
	if hasListPrefix {
		filterText = "- " + snippet.Label
	}

	return protocol.CompletionItem{
		Label:            snippet.Label,
		Kind:             protocol.CompletionItemKindSnippet,
		Detail:           snippet.Detail,
		Documentation:    snippet.Description,
		FilterText:       filterText,
		InsertTextFormat: protocol.InsertTextFormatSnippet,
		TextEdit: &protocol.TextEdit{
			Range:   replaceRange,
			NewText: applyIndentation(snippet.InsertText, indentation),
		},
	}
}

// =============================================================================
// Text Manipulation Helpers
// =============================================================================

// isFieldPrefix returns true if the prefix is a field-specific prefix (contains a dot).
func isFieldPrefix(prefix string) bool {
	return prefix != "" && strings.Contains(prefix, ".")
}

// extractIndentation returns the leading whitespace (spaces and tabs) from the line.
func extractIndentation(line string) string {
	for i, ch := range line {
		if ch != ' ' && ch != '\t' {
			return line[:i]
		}
	}
	return line
}

// applyIndentation adds the given indentation to the beginning of each non-empty line.
func applyIndentation(text, indentation string) string {
	if indentation == "" {
		return text
	}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if line != "" || i == 0 {
			lines[i] = indentation + line
		}
	}
	return strings.Join(lines, "\n")
}

// =============================================================================
// Word Extraction Helpers
// =============================================================================

// extractCurrentWord extracts the current word from the line based on word range.
func extractCurrentWord(currentLine string, wordRange document.WordRange) string {
	if wordRange.Start >= 0 && wordRange.Start < wordRange.End && wordRange.End <= len(currentLine) {
		return currentLine[wordRange.Start:wordRange.End]
	}
	return ""
}

// detectCursorAfterWord detects if cursor is after a complete word followed by whitespace.
// Returns true when cursor is positioned immediately after a word end and either:
// - at end of line, or
// - followed by a non-word character.
func detectCursorAfterWord(currentLine string, char int, wordRange document.WordRange, currentWord string) bool {
	if char != wordRange.End || currentWord == "" {
		return false
	}
	if char >= len(currentLine) {
		return true
	}
	return !schema.IsWordCharByte(currentLine[char])
}
