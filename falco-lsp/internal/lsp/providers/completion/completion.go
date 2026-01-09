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

	"github.com/c2ndev/falco-lsp/internal/config"
	"github.com/c2ndev/falco-lsp/internal/fields"
	"github.com/c2ndev/falco-lsp/internal/lsp/document"
	"github.com/c2ndev/falco-lsp/internal/lsp/protocol"
	"github.com/c2ndev/falco-lsp/internal/schema"
)

const requiredSuffix = " (required)"

// Provider handles code completion requests.
type Provider struct {
	documents          *document.Store
	maxCompletionItems int
}

// New creates a new completion provider.
func New(docs *document.Store, maxItems int) *Provider {
	if maxItems <= 0 {
		maxItems = config.DefaultMaxCompletionItems
	}
	return &Provider{
		documents:          docs,
		maxCompletionItems: maxItems,
	}
}

// GetCompletions returns completion items for the given position.
func (p *Provider) GetCompletions(doc *document.Document, params protocol.CompletionParams) []protocol.CompletionItem {
	if doc == nil {
		return nil
	}

	lines := doc.GetLines()
	// Validate line bounds
	if params.Position.Line < 0 || params.Position.Line >= len(lines) {
		return nil
	}

	currentLine := lines[params.Position.Line]
	// Clamp character to valid range
	char := params.Position.Character
	if char < 0 {
		char = 0
	}
	if char > len(currentLine) {
		char = len(currentLine)
	}
	linePrefix := currentLine[:char]

	// Get semantic context
	ctx := p.getSemanticContext(lines, params.Position.Line)
	wordRange := document.GetWordRangeAtPosition(currentLine, char)

	// Extract the current word/prefix being typed for filtering
	currentWord := ""
	if wordRange.Start >= 0 && wordRange.Start < wordRange.End && wordRange.End <= len(currentLine) {
		currentWord = currentLine[wordRange.Start:wordRange.End]
	}

	var items []protocol.CompletionItem

	// Provide completions based on context
	switch ctx.PropertyContext {
	case schema.PropPriority.String():
		items = p.getPriorityCompletions()
	case schema.PropSource.String():
		items = p.getSourceCompletions()
	case schema.PropEnabled.String(), schema.PropAppend.String(),
		schema.PropSkipIfUnknown.String(), schema.PropCapture.String():
		items = p.getBooleanCompletions()
	case schema.PropCondition.String():
		items = p.getConditionCompletions(currentWord)
	case schema.PropOutput.String():
		items = p.getOutputCompletions(currentWord)
	case schema.PropTags.String():
		items = p.getTagsCompletions()
	case schema.PropItems.String():
		items = p.getListItemCompletions()
	case schema.ExceptionContextName.String():
		items = []protocol.CompletionItem{{
			Label:  "name",
			Kind:   protocol.CompletionItemKindProperty,
			Detail: "Exception name",
		}}
	case schema.ExceptionContextFields.String():
		items = p.getConditionFieldCompletions()
	case schema.ExceptionContextComps.String():
		items = p.getComparisonOperatorCompletions()
	case schema.ExceptionContextValues.String():
		items = nil
	case schema.PropExceptions.String():
		items = p.getExceptionPropertyCompletions()
	case schema.PropRequiredPluginVersions.String():
		items = p.getPluginVersionCompletions()
	case schema.PropOverride.String():
		items = p.getOverridePropertyCompletions()
	default:
		switch ctx.BlockContext {
		case schema.BlockRule.String():
			items = p.getRulePropertyCompletions()
		case schema.BlockMacro.String():
			items = p.getMacroPropertyCompletions()
		case schema.BlockList.String():
			items = p.getListPropertyCompletions()
		case schema.BlockException.String():
			items = p.getExceptionPropertyCompletions()
		default:
			items = p.getTopLevelCompletions(linePrefix, params.Position)
		}
	}

	// Add TextEdit to items that don't have one
	for i := range items {
		if items[i].TextEdit != nil {
			continue
		}

		textToInsert := items[i].InsertText
		if textToInsert == "" {
			textToInsert = items[i].Label
		}

		items[i].TextEdit = &protocol.TextEdit{
			Range: protocol.Range{
				Start: protocol.Position{Line: params.Position.Line, Character: wordRange.Start},
				End:   protocol.Position{Line: params.Position.Line, Character: wordRange.End},
			},
			NewText: textToInsert,
		}
		items[i].InsertText = ""
	}

	return items
}

// SemanticContext holds the semantic context for completion.
type SemanticContext struct {
	BlockContext    string
	PropertyContext string
	IndentLevel     int
	InMultiLine     bool
}

// blockScanResult holds the result of scanning for block context.
type blockScanResult struct {
	blockContext     string
	propertyName     string
	inMultiLine      bool
	inExceptionBlock bool
}

// getSemanticContext analyzes the document to determine semantic context.
func (p *Provider) getSemanticContext(lines []string, currentLine int) SemanticContext {
	ctx := SemanticContext{
		BlockContext:    "top",
		PropertyContext: "",
		IndentLevel:     0,
		InMultiLine:     false,
	}

	if currentLine >= len(lines) {
		return ctx
	}

	currentLineText := lines[currentLine]
	ctx.IndentLevel = countIndent(currentLineText)

	// Scan backwards to find block and property context
	scanResult := p.scanBlockContext(lines, currentLine, ctx.IndentLevel)
	ctx.BlockContext = scanResult.blockContext
	ctx.InMultiLine = scanResult.inMultiLine

	// Resolve property context from the scan result
	if scanResult.propertyName != "" {
		ctx.PropertyContext = resolvePropertyContext(scanResult.propertyName, scanResult.inExceptionBlock)
	}

	// Check current line for property context (overrides scan result)
	if propCtx := checkCurrentLineProperty(currentLineText); propCtx != "" {
		ctx.PropertyContext = propCtx
	}

	return ctx
}

// scanBlockContext scans backwards through lines to find block context.
func (p *Provider) scanBlockContext(lines []string, currentLine, indentLevel int) blockScanResult {
	result := blockScanResult{blockContext: "top"}

	var propertyLine = -1
	var exceptionIndent = -1

	for i := currentLine; i >= 0; i-- {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		indent := countIndent(line)

		if trimmed == "" {
			continue
		}

		// Check for exception block
		if strings.HasPrefix(trimmed, "exceptions:") && !result.inExceptionBlock {
			result.inExceptionBlock = true
			exceptionIndent = indent
		}

		if result.inExceptionBlock && strings.HasPrefix(trimmed, "- name:") && indent > exceptionIndent {
			result.blockContext = "exception"
		}

		// Check for block start
		if blockCtx := detectBlockStart(trimmed, i, currentLine, indent, indentLevel); blockCtx != "" {
			result.blockContext = blockCtx
			break
		}

		// Check for property context
		if propertyLine == -1 && indent < indentLevel {
			if propName, isMultiLine := extractPropertyName(trimmed, line); propName != "" {
				result.propertyName = propName
				result.inMultiLine = isMultiLine
				propertyLine = i
			}
		}
	}

	return result
}

// detectBlockStart checks if a line starts a block (rule, macro, list, etc.).
func detectBlockStart(trimmed string, lineIndex, currentLine, indent, indentLevel int) string {
	blockPrefixes := []struct {
		prefix string
		block  string
	}{
		{"- rule:", "rule"},
		{"- macro:", "macro"},
		{"- list:", "list"},
		{"- required_engine_version:", "engine_version"},
	}

	for _, bp := range blockPrefixes {
		if strings.HasPrefix(trimmed, bp.prefix) {
			if lineIndex == currentLine || indent < indentLevel {
				return bp.block
			}
		}
	}

	// Special case for required_plugin_versions (returns as property context, not block)
	if strings.HasPrefix(trimmed, "- required_plugin_versions:") {
		if lineIndex == currentLine || indent < indentLevel {
			return "required_plugin_versions"
		}
	}

	return ""
}

// extractPropertyName extracts the property name from a line.
func extractPropertyName(trimmed, fullLine string) (string, bool) {
	colonIdx := strings.Index(trimmed, ":")
	if colonIdx <= 0 {
		return "", false
	}

	propName := strings.TrimPrefix(trimmed, "- ")
	if colonIdx2 := strings.Index(propName, ":"); colonIdx2 > 0 {
		propName = propName[:colonIdx2]
	}
	propName = strings.TrimSpace(propName)

	// Check for multi-line indicator
	isMultiLine := false
	if idx := strings.Index(fullLine, ":"); idx >= 0 {
		afterColon := strings.TrimSpace(fullLine[idx+1:])
		if afterColon == "|" || afterColon == ">" || afterColon == "|+" || afterColon == ">-" {
			isMultiLine = true
		}
	}

	return propName, isMultiLine
}

// resolvePropertyContext maps a property name to its context.
func resolvePropertyContext(propertyName string, inExceptionBlock bool) string {
	switch propertyName {
	case schema.PropCondition.String():
		return schema.PropCondition.String()
	case schema.PropOutput.String():
		return schema.PropOutput.String()
	case schema.PropPriority.String():
		return schema.PropPriority.String()
	case schema.PropSource.String():
		return schema.PropSource.String()
	case schema.PropTags.String():
		return schema.PropTags.String()
	case schema.PropEnabled.String(), schema.PropAppend.String(),
		schema.PropSkipIfUnknown.String(), schema.PropCapture.String():
		return propertyName
	case schema.PropItems.String():
		return schema.PropItems.String()
	case schema.PropExceptions.String():
		return schema.PropExceptions.String()
	case schema.PropOverride.String():
		return schema.PropOverride.String()
	case "fields":
		if inExceptionBlock {
			return schema.ExceptionContextFields.String()
		}
	case "comps":
		if inExceptionBlock {
			return schema.ExceptionContextComps.String()
		}
	case "values":
		if inExceptionBlock {
			return schema.ExceptionContextValues.String()
		}
	case "name":
		if inExceptionBlock {
			return schema.ExceptionContextName.String()
		}
	}
	return ""
}

// checkCurrentLineProperty checks the current line for property context.
func checkCurrentLineProperty(currentLineText string) string {
	currentTrimmed := strings.TrimSpace(currentLineText)
	colonIdx := strings.Index(currentTrimmed, ":")
	if colonIdx <= 0 {
		return ""
	}

	propName := strings.TrimPrefix(currentTrimmed, "- ")
	if colonIdx2 := strings.Index(propName, ":"); colonIdx2 > 0 {
		propName = propName[:colonIdx2]
	}
	propName = strings.TrimSpace(propName)

	switch propName {
	case schema.PropPriority.String():
		return schema.PropPriority.String()
	case schema.PropSource.String():
		return schema.PropSource.String()
	case schema.PropEnabled.String(), schema.PropAppend.String(), schema.PropSkipIfUnknown.String():
		return propName
	case schema.PropCondition.String():
		return schema.PropCondition.String()
	case schema.PropOutput.String():
		return schema.PropOutput.String()
	case schema.PropTags.String():
		return schema.PropTags.String()
	default:
		return ""
	}
}

func countIndent(line string) int {
	count := 0
	for _, ch := range line {
		switch ch {
		case ' ':
			count++
		case '\t':
			count += 2
		default:
			return count
		}
	}
	return count
}

func (p *Provider) getPriorityCompletions() []protocol.CompletionItem {
	items := make([]protocol.CompletionItem, 0, len(schema.AllPriorities))
	for _, pr := range schema.AllPriorities {
		items = append(items, protocol.CompletionItem{
			Label:         pr.Level.String(),
			Kind:          protocol.CompletionItemKindValue,
			Detail:        schema.PropPriority.String(),
			Documentation: pr.Description,
		})
	}
	return items
}

func (p *Provider) getSourceCompletions() []protocol.CompletionItem {
	items := make([]protocol.CompletionItem, 0, len(schema.AllSources))
	for _, s := range schema.AllSources {
		items = append(items, protocol.CompletionItem{
			Label:         s.Type.String(),
			Kind:          protocol.CompletionItemKindValue,
			Detail:        schema.PropSource.String(),
			Documentation: s.Description,
		})
	}
	return items
}

func (p *Provider) getBooleanCompletions() []protocol.CompletionItem {
	return []protocol.CompletionItem{
		{Label: "true", Kind: protocol.CompletionItemKindValue},
		{Label: "false", Kind: protocol.CompletionItemKindValue},
	}
}

func (p *Provider) getConditionCompletions(prefix string) []protocol.CompletionItem {
	items := make([]protocol.CompletionItem, 0, p.maxCompletionItems)

	// Add all Falco fields (with optional filtering by prefix)
	allFields := fields.GetAllFields()
	for _, f := range allFields {
		// If a prefix is provided (e.g., "ct."), filter fields to match
		if prefix != "" && !strings.HasPrefix(f.Name, prefix) {
			continue
		}
		items = append(items, protocol.CompletionItem{
			Label:         f.Name,
			Kind:          protocol.CompletionItemKindField,
			Detail:        f.Type,
			Documentation: f.Description,
			FilterText:    f.Name, // Explicitly set filter text
		})
	}

	// Add logical operators (only if no specific field prefix)
	if prefix == "" || !strings.Contains(prefix, ".") {
		for _, op := range schema.LogicalOperators {
			items = append(items, protocol.CompletionItem{
				Label:         op.Name,
				Kind:          protocol.CompletionItemKindKeyword,
				Detail:        op.Category,
				Documentation: op.Description,
			})
		}
	}

	// Add comparison operators (only if no specific field prefix)
	if prefix == "" || !strings.Contains(prefix, ".") {
		for _, op := range schema.ComparisonOperators {
			items = append(items, protocol.CompletionItem{
				Label:         op.Name,
				Kind:          protocol.CompletionItemKindOperator,
				Detail:        op.Category,
				Documentation: op.Description,
			})
		}
	}

	// Add macros and lists from analyzer (only if no specific field prefix)
	if prefix == "" || !strings.Contains(prefix, ".") {
		items = append(items, p.getMacroCompletions()...)
		items = append(items, p.getListCompletions()...)

		// Add common event types
		for _, evt := range schema.AllEventTypes() {
			items = append(items, protocol.CompletionItem{
				Label:         evt.Name,
				Kind:          protocol.CompletionItemKindValue,
				Detail:        evt.Category,
				Documentation: evt.Description,
			})
		}
	}

	return items
}

func (p *Provider) getOutputCompletions(prefix string) []protocol.CompletionItem {
	allFields := fields.GetAllFields()
	items := make([]protocol.CompletionItem, 0, len(allFields))

	// Remove leading % if present in prefix for matching
	matchPrefix := strings.TrimPrefix(prefix, "%")

	for _, f := range allFields {
		// If a prefix is provided (e.g., "%ct."), filter fields to match
		if matchPrefix != "" && !strings.HasPrefix(f.Name, matchPrefix) {
			continue
		}
		items = append(items, protocol.CompletionItem{
			Label:         "%" + f.Name,
			Kind:          protocol.CompletionItemKindField,
			Detail:        f.Type,
			Documentation: f.Description,
			InsertText:    "%" + f.Name,
			FilterText:    "%" + f.Name, // Explicitly set filter text
		})
	}
	return items
}

func (p *Provider) getTagsCompletions() []protocol.CompletionItem {
	allTags := schema.AllTags()
	items := make([]protocol.CompletionItem, 0, len(allTags))
	for _, t := range allTags {
		items = append(items, protocol.CompletionItem{
			Label:         t.Name,
			Kind:          protocol.CompletionItemKindValue,
			Detail:        "tag",
			Documentation: t.Description,
		})
	}
	return items
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
	allFields := fields.GetAllFields()
	items := make([]protocol.CompletionItem, 0, len(allFields))
	for _, f := range allFields {
		items = append(items, protocol.CompletionItem{
			Label:         f.Name,
			Kind:          protocol.CompletionItemKindField,
			Detail:        f.Type,
			Documentation: f.Description,
		})
	}
	return items
}

func (p *Provider) getComparisonOperatorCompletions() []protocol.CompletionItem {
	items := make([]protocol.CompletionItem, 0, len(schema.ComparisonOperators))
	for _, op := range schema.ComparisonOperators {
		items = append(items, protocol.CompletionItem{
			Label:         op.Name,
			Kind:          protocol.CompletionItemKindOperator,
			Detail:        op.Category,
			Documentation: op.Description,
		})
	}
	return items
}

func (p *Provider) getExceptionPropertyCompletions() []protocol.CompletionItem {
	items := make([]protocol.CompletionItem, 0, len(schema.ExceptionProperties))
	for _, prop := range schema.ExceptionProperties {
		items = append(items, protocol.CompletionItem{
			Label:         prop.Name.String(),
			Kind:          protocol.CompletionItemKindProperty,
			Detail:        "exception property",
			Documentation: prop.Description,
			InsertText:    prop.Name.String() + ": ",
		})
	}
	return items
}

func (p *Provider) getPluginVersionCompletions() []protocol.CompletionItem {
	return []protocol.CompletionItem{
		{Label: "name", Kind: protocol.CompletionItemKindProperty, Detail: "Plugin name", InsertText: "name: "},
		{Label: "version", Kind: protocol.CompletionItemKindProperty, Detail: "Plugin version", InsertText: "version: "},
	}
}

func (p *Provider) getOverridePropertyCompletions() []protocol.CompletionItem {
	items := make([]protocol.CompletionItem, 0, len(schema.OverrideableProperties))
	for _, prop := range schema.OverrideableProperties {
		items = append(items, protocol.CompletionItem{
			Label:      prop.Name.String(),
			Kind:       protocol.CompletionItemKindProperty,
			Detail:     prop.Description,
			InsertText: prop.Name.String() + ": replace",
		})
	}
	return items
}

func (p *Provider) getRulePropertyCompletions() []protocol.CompletionItem {
	items := make([]protocol.CompletionItem, 0, len(schema.RuleProperties))
	for _, prop := range schema.RuleProperties {
		detail := prop.Description
		if prop.Required {
			detail += requiredSuffix
		}
		items = append(items, protocol.CompletionItem{
			Label:      prop.Name.String(),
			Kind:       protocol.CompletionItemKindProperty,
			Detail:     detail,
			InsertText: prop.Name.String() + ": ",
		})
	}
	return items
}

func (p *Provider) getMacroPropertyCompletions() []protocol.CompletionItem {
	items := make([]protocol.CompletionItem, 0, len(schema.MacroProperties))
	for _, prop := range schema.MacroProperties {
		detail := prop.Description
		if prop.Required {
			detail += requiredSuffix
		}
		items = append(items, protocol.CompletionItem{
			Label:      prop.Name.String(),
			Kind:       protocol.CompletionItemKindProperty,
			Detail:     detail,
			InsertText: prop.Name.String() + ": ",
		})
	}
	return items
}

func (p *Provider) getListPropertyCompletions() []protocol.CompletionItem {
	items := make([]protocol.CompletionItem, 0, len(schema.ListProperties))
	for _, prop := range schema.ListProperties {
		detail := prop.Description
		if prop.Required {
			detail += requiredSuffix
		}
		items = append(items, protocol.CompletionItem{
			Label:      prop.Name.String(),
			Kind:       protocol.CompletionItemKindProperty,
			Detail:     detail,
			InsertText: prop.Name.String() + ": ",
		})
	}
	return items
}

func (p *Provider) getMacroCompletions() []protocol.CompletionItem {
	symbols := p.documents.GetAllSymbols()
	if symbols == nil {
		return nil
	}

	items := make([]protocol.CompletionItem, 0, len(symbols.Macros))
	for name, macro := range symbols.Macros {
		items = append(items, protocol.CompletionItem{
			Label:         name,
			Kind:          protocol.CompletionItemKindFunction,
			Detail:        "macro",
			Documentation: fmt.Sprintf("User-defined macro: %s", macro.Condition),
		})
	}
	return items
}

func (p *Provider) getListCompletions() []protocol.CompletionItem {
	symbols := p.documents.GetAllSymbols()
	if symbols == nil {
		return nil
	}

	items := make([]protocol.CompletionItem, 0, len(symbols.Lists))
	for name, list := range symbols.Lists {
		preview := ""
		if len(list.Items) > 0 {
			previewItems := list.Items
			if len(previewItems) > 3 {
				previewItems = previewItems[:3]
			}
			preview = fmt.Sprintf(" [%s...]", strings.Join(previewItems, ", "))
		}
		items = append(items, protocol.CompletionItem{
			Label:         name,
			Kind:          protocol.CompletionItemKindVariable,
			Detail:        "list",
			Documentation: fmt.Sprintf("User-defined list%s", preview),
		})
	}
	return items
}

func (p *Provider) getTopLevelCompletions(linePrefix string, position protocol.Position) []protocol.CompletionItem {
	trimmed := strings.TrimSpace(linePrefix)
	items := make([]protocol.CompletionItem, 0, 8)

	// Calculate indentation
	indentation := ""
	for _, ch := range linePrefix {
		switch ch {
		case ' ', '\t':
			indentation += string(ch)
		default:
			goto doneIndent
		}
	}
doneIndent:

	hasListPrefix := strings.HasPrefix(trimmed, "-")

	var replaceRange protocol.Range
	var filterPrefix string

	if hasListPrefix {
		dashIndex := strings.Index(linePrefix, "-")
		if dashIndex >= 0 {
			replaceRange = protocol.Range{
				Start: protocol.Position{Line: position.Line, Character: dashIndex},
				End:   position,
			}
			filterPrefix = "- "
		}
	} else {
		wordStart := len(linePrefix)
		for i := len(linePrefix) - 1; i >= 0; i-- {
			ch := linePrefix[i]
			if ch == ' ' || ch == '\t' {
				wordStart = i + 1
				break
			}
			if i == 0 {
				wordStart = 0
			}
		}
		replaceRange = protocol.Range{
			Start: protocol.Position{Line: position.Line, Character: wordStart},
			End:   position,
		}
		filterPrefix = ""
	}

	topLevelItems := []struct {
		label      string
		kind       int
		detail     string
		insertText string
	}{
		{"rule", protocol.CompletionItemKindClass, "Define a detection rule", "- rule: "},
		{"macro", protocol.CompletionItemKindFunction, "Define a reusable condition macro", "- macro: "},
		{"list", protocol.CompletionItemKindVariable, "Define a list of values", "- list: "},
		{"required_engine_version", protocol.CompletionItemKindConstant,
			"Specify minimum Falco engine version", "- required_engine_version: "},
		{"required_plugin_versions", protocol.CompletionItemKindConstant,
			"Specify required plugin versions", "- required_plugin_versions:\n  - name: \n    version: "},
	}

	for _, item := range topLevelItems {
		newText := applyIndentation(item.insertText, indentation)

		items = append(items, protocol.CompletionItem{
			Label:            item.label,
			Kind:             item.kind,
			Detail:           item.detail,
			InsertTextFormat: protocol.InsertTextFormatPlainText,
			TextEdit: &protocol.TextEdit{
				Range:   replaceRange,
				NewText: newText,
			},
			FilterText: filterPrefix + item.label,
		})
	}

	// Add full block snippets
	if trimmed == "-" || trimmed == "" {
		snippets := []struct {
			label      string
			detail     string
			insertText string
		}{
			{"rule (full)", "New detection rule with template", `- rule: $1
  desc: $2
  condition: $3
  output: "$4"
  priority: WARNING
  source: syscall
  tags: [$5]`},
			{"macro (full)", "New macro with template", `- macro: $1
  condition: $2`},
			{"list (full)", "New list with template", `- list: $1
  items: [$2]`},
		}

		for _, snippet := range snippets {
			newText := applyIndentation(snippet.insertText, indentation)

			items = append(items, protocol.CompletionItem{
				Label:            snippet.label,
				Kind:             protocol.CompletionItemKindSnippet,
				Detail:           snippet.detail,
				FilterText:       filterPrefix + strings.TrimSuffix(snippet.label, " (full)"),
				InsertTextFormat: protocol.InsertTextFormatSnippet,
				TextEdit: &protocol.TextEdit{
					Range:   replaceRange,
					NewText: newText,
				},
			})
		}
	}

	return items
}

func applyIndentation(text, indentation string) string {
	if indentation == "" || !strings.Contains(text, "\n") {
		if indentation != "" {
			return indentation + text
		}
		return text
	}

	lines := strings.Split(text, "\n")
	for i := range lines {
		if i == 0 {
			lines[i] = indentation + lines[i]
		} else if lines[i] != "" {
			lines[i] = indentation + lines[i]
		}
	}
	return strings.Join(lines, "\n")
}
