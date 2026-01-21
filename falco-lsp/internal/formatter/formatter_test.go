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

package formatter

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	assert.Equal(t, 2, opts.TabSize, "expected TabSize 2")
	assert.True(t, opts.InsertSpaces, "expected InsertSpaces true")
	assert.True(t, opts.TrimTrailingWhitespace, "expected TrimTrailingWhitespace true")
	assert.True(t, opts.InsertFinalNewline, "expected InsertFinalNewline true")
}

func TestFormat_EmptyContent(t *testing.T) {
	result := Format("", DefaultOptions())
	assert.Empty(t, result, "expected empty string")
}

func TestFormat_TrailingWhitespace(t *testing.T) {
	input := "- rule: test   \n  desc: hello   \n"
	opts := DefaultOptions()
	result := Format(input, opts)

	assert.NotContains(t, result, "   \n", "trailing whitespace should be removed")
}

func TestFormat_FinalNewline(t *testing.T) {
	input := "- rule: test\n  desc: hello"
	opts := DefaultOptions()
	result := Format(input, opts)

	assert.True(t, strings.HasSuffix(result, "\n"), "result should end with newline")
}

func TestFormat_NormalizeLineEndings(t *testing.T) {
	input := "- rule: test\r\n  desc: hello\r\n"
	opts := DefaultOptions()
	result := Format(input, opts)

	assert.NotContains(t, result, "\r", "CRLF should be normalized to LF")
}

func TestFormat_MultipleBlankLines(t *testing.T) {
	input := "- rule: test\n\n\n\n- macro: test2\n"
	opts := DefaultOptions()
	result := Format(input, opts)

	lines := strings.Split(result, "\n")
	blankCount := 0
	maxBlank := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			blankCount++
			if blankCount > maxBlank {
				maxBlank = blankCount
			}
		} else {
			blankCount = 0
		}
	}

	assert.LessOrEqual(t, maxBlank, 1, "should have at most 1 consecutive blank line")
}

func TestFormat_TabsToSpaces(t *testing.T) {
	input := "- rule: test\n\tdesc: hello\n"
	opts := DefaultOptions()
	result := Format(input, opts)

	assert.NotContains(t, result, "\t", "tabs should be converted to spaces")
	assert.Contains(t, result, "  desc:", "expected 2-space indent")
}

func TestFormat_PreserveTopLevel(t *testing.T) {
	input := "- rule: Test Rule\n  desc: Description\n"
	opts := DefaultOptions()
	result := Format(input, opts)

	assert.True(t, strings.HasPrefix(result, "- rule:"), "top-level rule should start at column 0")
}

func TestIsTopLevelItem(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"- rule: test", true},
		{"- macro: test", true},
		{"- list: test", true},
		{"- required_engine_version: 0.1.0", true},
		{"- required_plugin_versions:", true},
		{"desc: test", false},
		{"- item", false},
		{"rule: test", false},
	}

	for _, tt := range tests {
		result := isTopLevelItem(tt.input)
		assert.Equal(t, tt.expected, result, "isTopLevelItem(%q)", tt.input)
	}
}

func TestIsPropertyKey(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"desc: test", true},
		{"condition: true", true},
		{"priority: INFO", true},
		{"- item", false},
		{"- rule: test", false},
		{"no colon", false},
		{": no key", false},
	}

	for _, tt := range tests {
		result := isPropertyKey(tt.input)
		assert.Equal(t, tt.expected, result, "isPropertyKey(%q)", tt.input)
	}
}

func TestIsFormatted(t *testing.T) {
	opts := DefaultOptions()

	formatted := "- rule: test\n  desc: hello\n"
	assert.True(t, IsFormatted(formatted, opts), "expected content to be formatted")

	unformatted := "- rule: test   \n  desc: hello"
	assert.False(t, IsFormatted(unformatted, opts), "expected content to not be formatted")
}

func TestFormat_CompleteRule(t *testing.T) {
	input := `- rule: Shell Spawned
  desc: Detect shell
  condition: proc.name in (bash, sh)
  output: "Shell spawned"
  priority: WARNING
  tags: [container, shell]
`
	opts := DefaultOptions()
	result := Format(input, opts)

	assert.Contains(t, result, "- rule: Shell Spawned", "rule name should be preserved")
	assert.Contains(t, result, "  desc:", "desc should be indented")
}

func TestFormat_DisableNormalizeBlankLines(t *testing.T) {
	input := "- rule: test\n\n\n- macro: test2\n"
	opts := DefaultOptions()
	opts.NormalizeBlankLines = false
	result := Format(input, opts)

	lines := strings.Split(result, "\n")
	blankCount := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			blankCount++
		}
	}

	assert.GreaterOrEqual(t, blankCount, 2, "blank lines should be preserved when NormalizeBlankLines is false")
}

// --- formatContext tests ---

func TestFormatContext_PushPopCurrent(t *testing.T) {
	ctx := &formatContext{}

	assert.Equal(t, "", ctx.current(), "initial current should be empty")
	assert.Equal(t, 0, ctx.depth(), "initial depth should be 0")

	ctx.push("rule")
	assert.Equal(t, "rule", ctx.current(), "current should be rule")
	assert.Equal(t, 1, ctx.depth(), "depth should be 1")

	ctx.push("exceptions")
	assert.Equal(t, "exceptions", ctx.current(), "current should be exceptions")
	assert.Equal(t, 2, ctx.depth(), "depth should be 2")

	ctx.pop()
	assert.Equal(t, "rule", ctx.current(), "current should be rule after pop")
	assert.Equal(t, 1, ctx.depth(), "depth should be 1")

	ctx.pop()
	assert.Equal(t, "", ctx.current(), "current should be empty after pop")
	assert.Equal(t, 0, ctx.depth(), "depth should be 0")

	// Pop on empty stack should be safe
	ctx.pop()
	assert.Equal(t, "", ctx.current(), "pop on empty stack should be safe")
}

func TestFormatContext_PopTo(t *testing.T) {
	ctx := &formatContext{}
	ctx.push("rule")
	ctx.push("exceptions")
	ctx.push("exception_item")
	ctx.push("exception_values")

	assert.Equal(t, 4, ctx.depth(), "depth should be 4")

	ctx.popTo("exceptions")
	assert.Equal(t, "rule", ctx.current(), "current should be rule after popTo")
	assert.Equal(t, 1, ctx.depth(), "depth should be 1")
}

func TestFormatContext_PopTo_NotFound(t *testing.T) {
	ctx := &formatContext{}
	ctx.push("rule")
	ctx.push("exceptions")

	ctx.popTo("notfound")
	assert.Equal(t, 0, ctx.depth(), "depth should be 0 when target not found")
}

func TestFormatContext_Reset(t *testing.T) {
	ctx := &formatContext{}
	ctx.push("rule")
	ctx.push("exceptions")
	ctx.inMultiLine = true

	ctx.reset()
	assert.Equal(t, 0, ctx.depth(), "depth should be 0 after reset")
	assert.False(t, ctx.inMultiLine, "inMultiLine should be false after reset")
}

// --- Property check function tests ---

func TestIsNestedBlockProperty(t *testing.T) {
	tests := []struct {
		key      string
		expected bool
	}{
		{"exceptions", true},
		{"override", true},
		{"required_plugin_versions", true},
		{"desc", false},
		{"condition", false},
		{"priority", false},
	}

	for _, tt := range tests {
		result := isNestedBlockProperty(tt.key)
		assert.Equal(t, tt.expected, result, "isNestedBlockProperty(%q)", tt.key)
	}
}

func TestIsExceptionProperty(t *testing.T) {
	tests := []struct {
		key      string
		expected bool
	}{
		{"name", true},
		{"fields", true},
		{"comps", true},
		{"values", true},
		{"desc", false},
		{"condition", false},
	}

	for _, tt := range tests {
		result := isExceptionProperty(tt.key)
		assert.Equal(t, tt.expected, result, "isExceptionProperty(%q)", tt.key)
	}
}

func TestIsOverrideProperty(t *testing.T) {
	tests := []struct {
		key      string
		expected bool
	}{
		{"condition", true},
		{"output", true},
		{"priority", true},
		{"enabled", true},
		{"tags", true},
		{"exceptions", true},
		{"source", true},
		{"desc", false},   // not overrideable in current schema
		{"append", false}, // not overrideable
		{"rule", false},
	}

	for _, tt := range tests {
		result := isOverrideProperty(tt.key)
		assert.Equal(t, tt.expected, result, "isOverrideProperty(%q)", tt.key)
	}
}

func TestIsPluginVersionProperty(t *testing.T) {
	tests := []struct {
		key      string
		expected bool
	}{
		{"name", true},
		{"version", true},
		{"alternatives", true},
		{"desc", false},
		{"condition", false},
	}

	for _, tt := range tests {
		result := isPluginVersionProperty(tt.key)
		assert.Equal(t, tt.expected, result, "isPluginVersionProperty(%q)", tt.key)
	}
}

func TestIsAlternativeProperty(t *testing.T) {
	tests := []struct {
		key      string
		expected bool
	}{
		{"name", true},
		{"version", true},
		{"alternatives", false},
		{"desc", false},
	}

	for _, tt := range tests {
		result := isAlternativeProperty(tt.key)
		assert.Equal(t, tt.expected, result, "isAlternativeProperty(%q)", tt.key)
	}
}

func TestGetPropertyKey(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"desc: test", "desc"},
		{"condition: true", "condition"},
		{"priority: INFO", "priority"},
		{"- item", ""},
		{"- rule: test", ""},
		{"no colon", ""},
		{": no key", ""},
		{"key_with_dash-test: value", "key_with_dash-test"},
		{"_underscore: value", "_underscore"},
		{"123invalid: value", ""}, // starts with digit
	}

	for _, tt := range tests {
		result := getPropertyKey(tt.input)
		assert.Equal(t, tt.expected, result, "getPropertyKey(%q)", tt.input)
	}
}

func TestGetTopLevelBlockType(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"- rule: Test", "rule"},
		{"- macro: Test", "macro"},
		{"- list: Test", "list"},
		{"- required_plugin_versions:", "required_plugin_versions"},
		{"- required_engine_version: 0.1.0", "required_engine_version"},
		{"desc: test", ""},
		{"- item", ""},
	}

	for _, tt := range tests {
		result := getTopLevelBlockType(tt.input)
		assert.Equal(t, tt.expected, result, "getTopLevelBlockType(%q)", tt.input)
	}
}

func TestIsValidYAMLKey(t *testing.T) {
	tests := []struct {
		key      string
		expected bool
	}{
		{"desc", true},
		{"condition", true},
		{"_underscore", true},
		{"key_with_dash-test", true},
		{"key123", true},
		{"123invalid", false}, // starts with digit
		{"", false},
		{"has space", false},
		{"has:colon", false},
	}

	for _, tt := range tests {
		result := isValidYAMLKey(tt.key)
		assert.Equal(t, tt.expected, result, "isValidYAMLKey(%q)", tt.key)
	}
}

// --- shouldExitContext tests ---

func TestShouldExitContext(t *testing.T) {
	tests := []struct {
		key      string
		current  string
		expected bool
	}{
		// In exception_item, exception properties should not exit
		{"name", ctxExceptionItem, false},
		{"fields", ctxExceptionItem, false},
		{"comps", ctxExceptionItem, false},
		{"values", ctxExceptionItem, false},
		{"output", ctxExceptionItem, true}, // not an exception property

		// In plugin_version_item
		{"name", ctxPluginVersionItem, false},
		{"version", ctxPluginVersionItem, false},
		{"alternatives", ctxPluginVersionItem, false},
		{"output", ctxPluginVersionItem, true},

		// In alternative_item
		{"name", ctxAlternativeItem, false},
		{"version", ctxAlternativeItem, false},
		{"alternatives", ctxAlternativeItem, true}, // not valid in alternative

		// In override - condition, output, priority, tags, enabled, exceptions, source are valid
		{"condition", ctxOverride, false},
		{"output", ctxOverride, false},
		{"desc", ctxOverride, true}, // desc is not overrideable

		// In exception_values - any property exits
		{"name", ctxExceptionValues, true},
		{"values", ctxExceptionValues, true},

		// Default context
		{"output", "rule", false},
	}

	for _, tt := range tests {
		result := shouldExitContext(tt.key, tt.current)
		assert.Equal(t, tt.expected, result, "shouldExitContext(%q, %q)", tt.key, tt.current)
	}
}

// --- exitContext tests ---

func TestExitContext(t *testing.T) {
	t.Run("exit from exception_values to exception property", func(t *testing.T) {
		ctx := &formatContext{}
		ctx.push("rule")
		ctx.push(ctxExceptions)
		ctx.push(ctxExceptionItem)
		ctx.push(ctxExceptionValues)

		exitContext("name", ctx) // exception property
		assert.Equal(t, ctxExceptionItem, ctx.current(), "should stay in exception_item")
	})

	t.Run("exit from exception_values to non-exception property", func(t *testing.T) {
		ctx := &formatContext{}
		ctx.push("rule")
		ctx.push(ctxExceptions)
		ctx.push(ctxExceptionItem)
		ctx.push(ctxExceptionValues)

		exitContext("desc", ctx) // not an exception property
		assert.Equal(t, "rule", ctx.current(), "should exit to rule")
	})

	t.Run("exit from exception_item", func(t *testing.T) {
		ctx := &formatContext{}
		ctx.push("rule")
		ctx.push(ctxExceptions)
		ctx.push(ctxExceptionItem)

		exitContext("desc", ctx)
		assert.Equal(t, "rule", ctx.current(), "should exit to rule")
	})

	t.Run("exit from override", func(t *testing.T) {
		ctx := &formatContext{}
		ctx.push("rule")
		ctx.push(ctxOverride)

		exitContext("exceptions", ctx)
		assert.Equal(t, "rule", ctx.current(), "should exit to rule")
	})

	t.Run("exit from plugin_version_item", func(t *testing.T) {
		ctx := &formatContext{}
		ctx.push(ctxRequiredPluginVersions)
		ctx.push(ctxPluginVersionItem)

		exitContext("desc", ctx)
		assert.Equal(t, "", ctx.current(), "should exit completely")
	})

	t.Run("exit from alternative_item", func(t *testing.T) {
		ctx := &formatContext{}
		ctx.push(ctxPluginVersionItem)
		ctx.push(ctxAlternatives)
		ctx.push(ctxAlternativeItem)

		exitContext("desc", ctx)
		assert.Equal(t, ctxPluginVersionItem, ctx.current(), "should exit to plugin_version_item")
	})
}

// --- Format comprehensive tests ---

func TestFormat_Exceptions(t *testing.T) {
	input := `- rule: Test Rule
  desc: Test description
  condition: true
  output: "test"
  priority: WARNING
  exceptions:
    - name: ex1
      fields: [proc.name]
      comps: [=]
      values:
        - [bash]
        - [sh]
    - name: ex2
      fields: [fd.name]
`
	opts := DefaultOptions()
	result := Format(input, opts)

	// Check proper indentation
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "- rule:") {
			assert.True(t, !strings.HasPrefix(line, " "), "rule should be at column 0")
		}
		if strings.HasPrefix(strings.TrimSpace(line), "exceptions:") {
			assert.True(t, strings.HasPrefix(line, "  "), "exceptions should be at level 1")
		}
		if strings.Contains(line, "- name: ex1") {
			assert.True(t, strings.HasPrefix(line, "    "), "exception item should be at level 2")
		}
		if strings.Contains(line, "fields:") && strings.Contains(line, "[proc.name]") {
			assert.True(t, strings.HasPrefix(line, "      "), "exception property should be at level 3")
		}
	}
}

func TestFormat_Override(t *testing.T) {
	input := `- rule: Test Rule
  override:
    condition: new_condition
    enabled: false
`
	opts := DefaultOptions()
	result := Format(input, opts)

	assert.Contains(t, result, "  override:", "override should be at level 1")
	assert.Contains(t, result, "    condition:", "override property should be at level 2")
}

func TestFormat_RequiredPluginVersions(t *testing.T) {
	input := `- required_plugin_versions:
  - name: cloudtrail
    version: 0.1.0
    alternatives:
      - name: cloudtrail-alt
        version: 0.2.0
`
	opts := DefaultOptions()
	result := Format(input, opts)

	assert.Contains(t, result, "- required_plugin_versions:", "should start at column 0")
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		if strings.Contains(line, "- name: cloudtrail") && !strings.Contains(line, "alt") {
			assert.True(t, strings.HasPrefix(line, "    "), "plugin item should be at level 2")
		}
		if strings.Contains(line, "alternatives:") {
			assert.True(t, strings.HasPrefix(line, "      "), "alternatives should be at level 3")
		}
	}
}

func TestFormat_MultiLineBlock(t *testing.T) {
	input := `- rule: Test Rule
  condition: |
    proc.name = "bash" and
    user.name = "root"
  output: "test"
`
	opts := DefaultOptions()
	result := Format(input, opts)

	// Multi-line content should be preserved as-is
	assert.Contains(t, result, "  condition: |", "condition with pipe should be at level 1")
	// The content after | should be preserved
	assert.Contains(t, result, "proc.name =", "multi-line content should be preserved")
}

func TestFormat_Comments(t *testing.T) {
	input := `# Top level comment
- rule: Test Rule
  # Property comment
  desc: Test
`
	opts := DefaultOptions()
	result := Format(input, opts)

	// Comments should be preserved
	assert.Contains(t, result, "# Top level comment", "top level comment should be preserved")
	assert.Contains(t, result, "# Property comment", "property comment should be preserved")
}

func TestFormat_ListProperty_Tags(t *testing.T) {
	input := `- rule: Test Rule
  desc: Test
  tags:
    - container
    - shell
`
	opts := DefaultOptions()
	result := Format(input, opts)

	assert.Contains(t, result, "  tags:", "tags should be at level 1")
}

func TestFormat_TabsInsteadOfSpaces(t *testing.T) {
	input := "- rule: test\n  desc: hello\n"
	opts := DefaultOptions()
	opts.InsertSpaces = false
	result := Format(input, opts)

	assert.Contains(t, result, "\tdesc:", "should use tabs for indent")
}

func TestFormat_CustomTabSize(t *testing.T) {
	input := "- rule: test\n    desc: hello\n"
	opts := DefaultOptions()
	opts.TabSize = 4
	result := Format(input, opts)

	lines := strings.Split(result, "\n")
	for _, line := range lines {
		if strings.Contains(line, "desc:") {
			assert.True(t, strings.HasPrefix(line, "    "), "should use 4 spaces for indent")
		}
	}
}

func TestFormat_DisableTrimTrailingWhitespace(t *testing.T) {
	input := "- rule: test   \n  desc: hello   \n"
	opts := DefaultOptions()
	opts.TrimTrailingWhitespace = false
	result := Format(input, opts)

	// When disabled, trailing whitespace should be preserved in the processing
	// but note that multiline blocks still have their content preserved
	require.NotEmpty(t, result)
}

func TestFormat_DisableFinalNewline(t *testing.T) {
	input := "- rule: test\n  desc: hello\n"
	opts := DefaultOptions()
	opts.InsertFinalNewline = false
	result := Format(input, opts)

	// Already has newline, so it should remain
	assert.True(t, strings.HasSuffix(result, "\n"), "existing newline should be kept")
}

func TestFormat_CarriageReturn(t *testing.T) {
	input := "- rule: test\r  desc: hello\r"
	opts := DefaultOptions()
	result := Format(input, opts)

	assert.NotContains(t, result, "\r", "CR should be normalized to LF")
}

func TestFormat_Macro(t *testing.T) {
	input := `- macro: shell_procs
  condition: proc.name in (bash, sh, zsh)
`
	opts := DefaultOptions()
	result := Format(input, opts)

	assert.True(t, strings.HasPrefix(result, "- macro:"), "macro should start at column 0")
	assert.Contains(t, result, "  condition:", "condition should be at level 1")
}

func TestFormat_List(t *testing.T) {
	input := `- list: shell_binaries
  items: [bash, sh, zsh]
`
	opts := DefaultOptions()
	result := Format(input, opts)

	assert.True(t, strings.HasPrefix(result, "- list:"), "list should start at column 0")
	assert.Contains(t, result, "  items:", "items should be at level 1")
}

func TestFormat_GenericListItem(t *testing.T) {
	ctx := &formatContext{}
	ctx.push("rule")
	indent := "  "

	result := formatListItem("- item", indent, ctx)
	assert.Equal(t, "  - item", result, "generic list item should be at depth 1")
}

func TestFormat_EmptyContextListItem(t *testing.T) {
	ctx := &formatContext{}
	indent := "  "

	result := formatListItem("- item", indent, ctx)
	assert.Equal(t, "  - item", result, "list item with empty context should default to depth 1")
}

func TestFormat_ItemsContext(t *testing.T) {
	ctx := &formatContext{}
	ctx.push("list")
	ctx.push("items")
	indent := "  "

	result := formatListItem("- bash", indent, ctx)
	assert.Equal(t, "    - bash", result, "items list item should be at level 2")
}

func TestFormat_TagsContext(t *testing.T) {
	ctx := &formatContext{}
	ctx.push("rule")
	ctx.push("tags")
	indent := "  "

	result := formatListItem("- container", indent, ctx)
	assert.Equal(t, "    - container", result, "tags list item should be at level 2")
}

func TestFormat_PropertyDefaultFallback(t *testing.T) {
	ctx := &formatContext{}
	indent := "  "

	result := formatProperty("unknown", "unknown: value", indent, ctx)
	assert.Equal(t, "  unknown: value", result, "fallback should use depth 1")
}

func TestFormat_PropertyInUnknownContext(t *testing.T) {
	ctx := &formatContext{}
	ctx.push("unknown_context")
	indent := "  "

	result := formatProperty("prop", "prop: value", indent, ctx)
	assert.Equal(t, "  prop: value", result, "property in unknown context should use depth")
}
