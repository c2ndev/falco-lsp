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
