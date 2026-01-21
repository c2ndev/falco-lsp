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
	"github.com/c2ndev/falco-lsp/internal/config"
	"github.com/c2ndev/falco-lsp/internal/lsp/document"
	"github.com/c2ndev/falco-lsp/internal/lsp/logging"
	"github.com/c2ndev/falco-lsp/internal/lsp/protocol"
	"github.com/c2ndev/falco-lsp/internal/schema"
)

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

// completionInput holds parsed input for completion processing.
type completionInput struct {
	lines           []string
	currentLine     string
	linePrefix      string
	char            int
	wordRange       document.WordRange
	currentWord     string
	cursorAfterWord bool
	ctx             SemanticContext
	position        protocol.Position
}

// GetCompletions returns completion items for the given position.
func (p *Provider) GetCompletions(doc *document.Document, params protocol.CompletionParams) []protocol.CompletionItem {
	input, ok := p.parseCompletionInput(doc, params)
	if !ok {
		return nil
	}

	logging.Debug("Completion context",
		"linePrefix", input.linePrefix,
		"currentWord", input.currentWord,
		"blockContext", input.ctx.BlockContext,
		"propertyContext", input.ctx.PropertyContext,
		"indentLevel", input.ctx.IndentLevel)

	items := p.getCompletionsByContext(&input)
	p.applyTextEdits(items, input.position, input.wordRange)

	return items
}

// parseCompletionInput validates and parses the completion request input.
func (p *Provider) parseCompletionInput(doc *document.Document, params protocol.CompletionParams) (completionInput, bool) {
	if doc == nil {
		return completionInput{}, false
	}

	lines := doc.GetLines()
	if params.Position.Line < 0 || params.Position.Line > len(lines) {
		return completionInput{}, false
	}

	currentLine := ""
	if params.Position.Line < len(lines) {
		currentLine = lines[params.Position.Line]
	}

	char := max(0, params.Position.Character)
	char = min(char, len(currentLine))
	linePrefix := currentLine[:char]

	ctx := getSemanticContext(lines, params.Position.Line)
	wordRange := document.GetWordRangeAtPosition(currentLine, char)
	currentWord := extractCurrentWord(currentLine, wordRange)
	cursorAfterWord := detectCursorAfterWord(currentLine, char, wordRange, currentWord)

	return completionInput{
		lines:           lines,
		currentLine:     currentLine,
		linePrefix:      linePrefix,
		char:            char,
		wordRange:       wordRange,
		currentWord:     currentWord,
		cursorAfterWord: cursorAfterWord,
		ctx:             ctx,
		position:        params.Position,
	}, true
}

// getCompletionsByContext returns completions based on the semantic context.
func (p *Provider) getCompletionsByContext(input *completionInput) []protocol.CompletionItem {
	if items := p.getPropertyContextCompletions(input); items != nil {
		return items
	}
	return p.getBlockContextCompletions(input)
}

// getPropertyContextCompletions returns completions for property contexts.
func (p *Provider) getPropertyContextCompletions(input *completionInput) []protocol.CompletionItem {
	switch input.ctx.PropertyContext {
	case schema.PropPriority.String():
		return p.getPriorityCompletions()
	case schema.PropSource.String():
		return p.getSourceCompletions()
	case schema.PropEnabled.String(), schema.PropAppend.String(),
		schema.PropSkipIfUnknown.String(), schema.PropCapture.String():
		return p.getBooleanCompletions()
	case schema.PropCondition.String():
		return p.getConditionCompletions(input.currentWord, input.cursorAfterWord)
	case schema.PropOutput.String():
		return p.getOutputCompletions(input.currentWord)
	case schema.PropTags.String():
		return p.getTagsCompletions()
	case schema.PropItems.String():
		return p.getListItemCompletions()
	case schema.ExceptionContextName.String():
		return newSinglePropertyCompletion(schema.PropExceptionName.String(), "Exception name")
	case schema.ExceptionContextFields.String():
		return p.getConditionFieldCompletions()
	case schema.ExceptionContextComps.String():
		return p.getComparisonOperatorCompletions()
	case schema.ExceptionContextValues.String():
		return nil
	case schema.PropExceptions.String():
		return p.getExceptionPropertyCompletions()
	case schema.PropRequiredPluginVersions.String():
		return p.getPluginVersionCompletions()
	case schema.PropOverride.String():
		return p.getOverridePropertyCompletions()
	default:
		return nil
	}
}

// getBlockContextCompletions returns completions for block contexts.
func (p *Provider) getBlockContextCompletions(input *completionInput) []protocol.CompletionItem {
	switch input.ctx.BlockContext {
	case schema.BlockRule.String():
		return p.getRulePropertyCompletions()
	case schema.BlockMacro.String():
		return p.getMacroPropertyCompletions()
	case schema.BlockList.String():
		return p.getListPropertyCompletions()
	case schema.BlockException.String():
		return p.getExceptionPropertyCompletions()
	default:
		return p.getTopLevelCompletions(input.linePrefix, input.position)
	}
}

// applyTextEdits adds TextEdit to items that don't have one.
func (p *Provider) applyTextEdits(items []protocol.CompletionItem, position protocol.Position, wordRange document.WordRange) {
	editRange := protocol.Range{
		Start: protocol.Position{Line: position.Line, Character: wordRange.Start},
		End:   protocol.Position{Line: position.Line, Character: wordRange.End},
	}
	for i := range items {
		if items[i].TextEdit != nil {
			continue
		}
		textToInsert := items[i].InsertText
		if textToInsert == "" {
			textToInsert = items[i].Label
		}
		items[i].TextEdit = &protocol.TextEdit{
			Range:   editRange,
			NewText: textToInsert,
		}
		items[i].InsertText = ""
	}
}
