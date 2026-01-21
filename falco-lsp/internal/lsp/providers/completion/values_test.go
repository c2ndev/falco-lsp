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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/c2ndev/falco-lsp/internal/lsp/protocol"
	"github.com/c2ndev/falco-lsp/internal/schema"
	"github.com/c2ndev/falco-lsp/internal/testutil"
)

// =============================================================================
// UNIT TESTS: getPriorityCompletions
// =============================================================================

func TestGetPriorityCompletions_ReturnsAllPriorities(t *testing.T) {
	p := valuesTestProvider()
	items := p.getPriorityCompletions()

	require.NotEmpty(t, items, "Should return priority completions")
	assert.GreaterOrEqual(t, len(items), 7, "Should have at least 7 priority levels")

	// Check for expected priorities (using Falco's syslog-style priority names)
	labels := valuesExtractLabels(items)
	assert.Contains(t, labels, "DEBUG", "Should contain DEBUG priority")
	assert.Contains(t, labels, "INFORMATIONAL", "Should contain INFORMATIONAL priority")
	assert.Contains(t, labels, "WARNING", "Should contain WARNING priority")
	assert.Contains(t, labels, "ERROR", "Should contain ERROR priority")
	assert.Contains(t, labels, "CRITICAL", "Should contain CRITICAL priority")
}

func TestGetPriorityCompletions_HasCorrectKind(t *testing.T) {
	p := valuesTestProvider()
	items := p.getPriorityCompletions()

	for _, item := range items {
		assert.Equal(t, protocol.CompletionItemKindValue, item.Kind,
			"Priority '%s' should have Value kind", item.Label)
	}
}

func TestGetPriorityCompletions_HasCorrectDetail(t *testing.T) {
	p := valuesTestProvider()
	items := p.getPriorityCompletions()

	for _, item := range items {
		assert.Equal(t, schema.PropPriority.String(), item.Detail,
			"Priority '%s' should have 'priority' as detail", item.Label)
	}
}

// =============================================================================
// UNIT TESTS: getSourceCompletions
// =============================================================================

func TestGetSourceCompletions_ReturnsAllSources(t *testing.T) {
	p := valuesTestProvider()
	items := p.getSourceCompletions()

	require.NotEmpty(t, items, "Should return source completions")

	labels := valuesExtractLabels(items)
	assert.Contains(t, labels, "syscall", "Should contain syscall source")
	assert.Contains(t, labels, "k8s_audit", "Should contain k8s_audit source")
}

func TestGetSourceCompletions_HasCorrectKind(t *testing.T) {
	p := valuesTestProvider()
	items := p.getSourceCompletions()

	for _, item := range items {
		assert.Equal(t, protocol.CompletionItemKindValue, item.Kind,
			"Source '%s' should have Value kind", item.Label)
	}
}

// =============================================================================
// UNIT TESTS: getBooleanCompletions
// =============================================================================

func TestGetBooleanCompletions_ReturnsTrueAndFalse(t *testing.T) {
	p := valuesTestProvider()
	items := p.getBooleanCompletions()

	require.Len(t, items, 2, "Should return exactly 2 boolean completions")

	labels := valuesExtractLabels(items)
	assert.Contains(t, labels, "true", "Should contain 'true'")
	assert.Contains(t, labels, "false", "Should contain 'false'")
}

func TestGetBooleanCompletions_HasCorrectKind(t *testing.T) {
	p := valuesTestProvider()
	items := p.getBooleanCompletions()

	for _, item := range items {
		assert.Equal(t, protocol.CompletionItemKindValue, item.Kind,
			"Boolean '%s' should have Value kind", item.Label)
	}
}

// =============================================================================
// UNIT TESTS: getConditionCompletions
// =============================================================================

func TestGetConditionCompletions_NoPrefix_ReturnsFields(t *testing.T) {
	p := valuesTestProvider()
	items := p.getConditionCompletions("", false)

	require.NotEmpty(t, items, "Should return completions")

	// Should include Falco fields
	hasField := false
	for _, item := range items {
		if item.Kind == protocol.CompletionItemKindField {
			hasField = true
			break
		}
	}
	assert.True(t, hasField, "Should include fields")
}

func TestGetConditionCompletions_NoPrefix_IncludesOperators(t *testing.T) {
	p := valuesTestProvider()
	items := p.getConditionCompletions("", false)

	// Should include operators
	hasOperator := false
	hasKeyword := false
	for _, item := range items {
		if item.Kind == protocol.CompletionItemKindOperator {
			hasOperator = true
		}
		if item.Kind == protocol.CompletionItemKindKeyword {
			hasKeyword = true
		}
	}
	assert.True(t, hasOperator, "Should include comparison operators")
	assert.True(t, hasKeyword, "Should include logical operators (keywords)")
}

func TestGetConditionCompletions_FieldPrefix_FiltersFields(t *testing.T) {
	p := valuesTestProvider()
	items := p.getConditionCompletions("proc.", false)

	require.NotEmpty(t, items, "Should return filtered fields")

	// All returned fields should start with "proc."
	for _, item := range items {
		if item.Kind == protocol.CompletionItemKindField {
			assert.True(t, len(item.Label) >= 4 && item.Label[:4] == "proc",
				"Field '%s' should start with 'proc'", item.Label)
		}
	}
}

func TestGetConditionCompletions_CursorAfterWord_ReturnsOperators(t *testing.T) {
	p := valuesTestProvider()
	items := p.getConditionCompletions("proc.name", true)

	require.NotEmpty(t, items, "Should return operator completions")

	// Should primarily return operators
	operatorCount := 0
	for _, item := range items {
		if item.Kind == protocol.CompletionItemKindOperator || item.Kind == protocol.CompletionItemKindKeyword {
			operatorCount++
		}
	}
	assert.Equal(t, len(items), operatorCount, "Should only return operators when cursor is after complete word")
}

// =============================================================================
// UNIT TESTS: getOutputCompletions
// =============================================================================

func TestGetOutputCompletions_ReturnsFields(t *testing.T) {
	p := valuesTestProvider()
	items := p.getOutputCompletions("")

	require.NotEmpty(t, items, "Should return field completions for output")

	// All items should be fields
	for _, item := range items {
		assert.Equal(t, protocol.CompletionItemKindField, item.Kind,
			"Output completion '%s' should have Field kind", item.Label)
	}
}

func TestGetOutputCompletions_WithPrefix_FiltersFields(t *testing.T) {
	p := valuesTestProvider()
	items := p.getOutputCompletions("proc.")

	require.NotEmpty(t, items, "Should return filtered fields")

	// For output completions, the labels have "%" prefix (e.g., "%proc.name")
	// So we check that the label contains "proc"
	for _, item := range items {
		assert.Contains(t, item.Label, "proc",
			"Field '%s' should contain 'proc'", item.Label)
	}
}

// =============================================================================
// UNIT TESTS: getTagsCompletions
// =============================================================================

func TestGetTagsCompletions_ReturnsAllTags(t *testing.T) {
	p := valuesTestProvider()
	items := p.getTagsCompletions()

	require.NotEmpty(t, items, "Should return tag completions")

	labels := valuesExtractLabels(items)
	// Check for some common tags
	assert.Contains(t, labels, "container", "Should contain 'container' tag")
	assert.Contains(t, labels, "network", "Should contain 'network' tag")
	assert.Contains(t, labels, "filesystem", "Should contain 'filesystem' tag")
}

func TestGetTagsCompletions_HasCorrectKind(t *testing.T) {
	p := valuesTestProvider()
	items := p.getTagsCompletions()

	for _, item := range items {
		assert.Equal(t, protocol.CompletionItemKindValue, item.Kind,
			"Tag '%s' should have Value kind", item.Label)
	}
}

// =============================================================================
// UNIT TESTS: getListItemCompletions
// =============================================================================

func TestGetListItemCompletions_ReturnsListsAndBinaries(t *testing.T) {
	p := valuesTestProviderWithSymbols(t)
	items := p.getListItemCompletions()

	require.NotEmpty(t, items, "Should return list item completions")

	// Should contain common binaries
	labels := valuesExtractLabels(items)
	hasBinary := false
	for _, b := range schema.CommonBinaries {
		if labels[b] {
			hasBinary = true
			break
		}
	}
	assert.True(t, hasBinary, "Should contain common binaries")
}

// =============================================================================
// UNIT TESTS: getConditionFieldCompletions
// =============================================================================

func TestGetConditionFieldCompletions_ReturnsAllFields(t *testing.T) {
	p := valuesTestProvider()
	items := p.getConditionFieldCompletions()

	require.NotEmpty(t, items, "Should return field completions")

	for _, item := range items {
		assert.Equal(t, protocol.CompletionItemKindField, item.Kind,
			"Field '%s' should have Field kind", item.Label)
	}
}

// =============================================================================
// UNIT TESTS: getComparisonOperatorCompletions
// =============================================================================

func TestGetComparisonOperatorCompletions_ReturnsAllOperators(t *testing.T) {
	p := valuesTestProvider()
	items := p.getComparisonOperatorCompletions()

	require.NotEmpty(t, items, "Should return operator completions")
	assert.Equal(t, len(schema.ComparisonOperators), len(items), "Should match schema operators count")

	for _, item := range items {
		assert.Equal(t, protocol.CompletionItemKindOperator, item.Kind,
			"Operator '%s' should have Operator kind", item.Label)
	}
}

// =============================================================================
// UNIT TESTS: getExceptionPropertyCompletions
// =============================================================================

func TestGetExceptionPropertyCompletions_ReturnsAllProperties(t *testing.T) {
	p := valuesTestProvider()
	items := p.getExceptionPropertyCompletions()

	require.NotEmpty(t, items, "Should return exception property completions")
	assert.Equal(t, len(schema.ExceptionProperties), len(items), "Should match schema properties count")
}

// =============================================================================
// UNIT TESTS: getPluginVersionCompletions
// =============================================================================

func TestGetPluginVersionCompletions_ReturnsAllProperties(t *testing.T) {
	p := valuesTestProvider()
	items := p.getPluginVersionCompletions()

	require.NotEmpty(t, items, "Should return plugin version property completions")
	assert.Equal(t, len(schema.PluginVersionProperties), len(items), "Should match schema properties count")
}

// =============================================================================
// UNIT TESTS: getOverridePropertyCompletions
// =============================================================================

func TestGetOverridePropertyCompletions_ReturnsAllProperties(t *testing.T) {
	p := valuesTestProvider()
	items := p.getOverridePropertyCompletions()

	require.NotEmpty(t, items, "Should return override property completions")
	assert.Equal(t, len(schema.OverrideableProperties), len(items), "Should match schema properties count")
}

func TestGetOverridePropertyCompletions_HasReplaceSuffix(t *testing.T) {
	p := valuesTestProvider()
	items := p.getOverridePropertyCompletions()

	for _, item := range items {
		assert.Contains(t, item.InsertText, ": replace",
			"Override property '%s' should have ': replace' suffix", item.Label)
	}
}

// =============================================================================
// UNIT TESTS: Block Property Completions
// =============================================================================

func TestGetRulePropertyCompletions_ReturnsAllProperties(t *testing.T) {
	p := valuesTestProvider()
	items := p.getRulePropertyCompletions()

	require.NotEmpty(t, items, "Should return rule property completions")
	assert.Equal(t, len(schema.RuleProperties), len(items), "Should match schema properties count")
}

func TestGetMacroPropertyCompletions_ReturnsAllProperties(t *testing.T) {
	p := valuesTestProvider()
	items := p.getMacroPropertyCompletions()

	require.NotEmpty(t, items, "Should return macro property completions")
	assert.Equal(t, len(schema.MacroProperties), len(items), "Should match schema properties count")
}

func TestGetListPropertyCompletions_ReturnsAllProperties(t *testing.T) {
	p := valuesTestProvider()
	items := p.getListPropertyCompletions()

	require.NotEmpty(t, items, "Should return list property completions")
	assert.Equal(t, len(schema.ListProperties), len(items), "Should match schema properties count")
}

// =============================================================================
// UNIT TESTS: Symbol Completions
// =============================================================================

func TestGetMacroCompletions_NoSymbols_ReturnsEmpty(t *testing.T) {
	p := valuesTestProvider()
	items := p.getMacroCompletions()

	assert.Empty(t, items, "Should return empty when no symbols")
}

func TestGetMacroCompletions_WithSymbols_ReturnsMacros(t *testing.T) {
	p := valuesTestProviderWithSymbols(t)
	items := p.getMacroCompletions()

	require.NotEmpty(t, items, "Should return macro completions")

	for _, item := range items {
		assert.Equal(t, protocol.CompletionItemKindFunction, item.Kind,
			"Macro '%s' should have Function kind", item.Label)
	}
}

func TestGetListCompletions_NoSymbols_ReturnsEmpty(t *testing.T) {
	p := valuesTestProvider()
	items := p.getListCompletions()

	assert.Empty(t, items, "Should return empty when no symbols")
}

func TestGetListCompletions_WithSymbols_ReturnsLists(t *testing.T) {
	p := valuesTestProviderWithSymbols(t)
	items := p.getListCompletions()

	require.NotEmpty(t, items, "Should return list completions")

	for _, item := range items {
		assert.Equal(t, protocol.CompletionItemKindVariable, item.Kind,
			"List '%s' should have Variable kind", item.Label)
	}
}

// =============================================================================
// UNIT TESTS: getTopLevelCompletions
// =============================================================================

func TestGetTopLevelCompletions_ReturnsSnippets(t *testing.T) {
	p := valuesTestProvider()
	pos := protocol.Position{Line: 0, Character: 0}
	items := p.getTopLevelCompletions("", pos)

	require.NotEmpty(t, items, "Should return top-level completions")
	assert.Equal(t, len(schema.AllSnippets), len(items), "Should match schema snippets count")

	// All should be snippets
	for _, item := range items {
		assert.Equal(t, protocol.CompletionItemKindSnippet, item.Kind,
			"Top-level completion '%s' should have Snippet kind", item.Label)
	}
}

func TestGetTopLevelCompletions_WithIndentation_PreservesIndent(t *testing.T) {
	p := valuesTestProvider()
	pos := protocol.Position{Line: 0, Character: 2}
	items := p.getTopLevelCompletions("  ", pos)

	require.NotEmpty(t, items, "Should return top-level completions with indentation")
}

func TestGetTopLevelCompletions_WithListPrefix_HandlesPrefix(t *testing.T) {
	p := valuesTestProvider()
	pos := protocol.Position{Line: 0, Character: 2}
	items := p.getTopLevelCompletions("- ", pos)

	require.NotEmpty(t, items, "Should return top-level completions with list prefix")
}

// =============================================================================
// TEST HELPERS
// =============================================================================

// valuesTestProvider creates a Provider with an empty document store for testing.
// This is named differently from newTestProvider in completion_test.go to avoid redeclaration.
func valuesTestProvider() *Provider {
	env := testutil.NewTestEnv()
	return New(env.Documents, 100)
}

// valuesTestProviderWithSymbols creates a Provider with a document store containing test symbols.
func valuesTestProviderWithSymbols(t *testing.T) *Provider {
	env := testutil.NewTestEnv()

	// Add a document with macros and lists to populate symbols
	content := `- macro: test_macro
  condition: proc.name = test

- macro: another_macro
  condition: fd.name contains /etc

- list: test_list
  items: [item1, item2]

- list: another_list
  items: [a, b, c]
`
	env.AddDocument(t, "test.yaml", content)
	return New(env.Documents, 100)
}

// valuesExtractLabels extracts labels from completion items into a map for easy lookup.
func valuesExtractLabels(items []protocol.CompletionItem) map[string]bool {
	labels := make(map[string]bool)
	for _, item := range items {
		labels[item.Label] = true
	}
	return labels
}
