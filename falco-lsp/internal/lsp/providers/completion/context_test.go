// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The Falco Authors
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
//

// Package completion provides code completion functionality.
package completion

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// UNIT TESTS: countIndent function
// =============================================================================

func TestCountIndent(t *testing.T) {
	tests := []struct {
		line     string
		expected int
	}{
		{"", 0},
		{"no indent", 0},
		{"  two spaces", 2},
		{"    four spaces", 4},
		{"\ttab", 2},
		{"\t\ttwo tabs", 4},
		{"  \t mixed", 5}, // 2 spaces + 1 tab (counts as 3) = 5
	}

	for _, tt := range tests {
		result := countIndent(tt.line)
		assert.Equal(t, tt.expected, result, "countIndent(%q) should return %d", tt.line, tt.expected)
	}
}

// =============================================================================
// UNIT TESTS: parsePropertyName function
// =============================================================================

func TestParsePropertyName_Empty(t *testing.T) {
	result := parsePropertyName("")
	assert.Equal(t, "", result, "Empty string should return empty")
}

func TestParsePropertyName_NoColon(t *testing.T) {
	result := parsePropertyName("no colon here")
	assert.Equal(t, "", result, "No colon should return empty")
}

func TestParsePropertyName_SimpleProperty(t *testing.T) {
	result := parsePropertyName("condition: something")
	assert.Equal(t, "condition", result, "Should extract property name before colon")
}

func TestParsePropertyName_WithDashPrefix(t *testing.T) {
	result := parsePropertyName("- rule: name")
	assert.Equal(t, "rule", result, "Should strip dash prefix and extract property name")
}

func TestParsePropertyName_WithWhitespace(t *testing.T) {
	result := parsePropertyName("  priority: WARNING  ")
	assert.Equal(t, "priority", result, "Should handle leading/trailing whitespace")
}

func TestParsePropertyName_ColonAtStart(t *testing.T) {
	result := parsePropertyName(": value")
	assert.Equal(t, "", result, "Colon at start should return empty")
}

// =============================================================================
// UNIT TESTS: isMultiLineIndicator function
// =============================================================================

func TestIsMultiLineIndicator_Empty(t *testing.T) {
	assert.False(t, isMultiLineIndicator(""), "Empty string is not multi-line")
}

func TestIsMultiLineIndicator_Pipe(t *testing.T) {
	assert.True(t, isMultiLineIndicator("|"), "Pipe is multi-line indicator")
}

func TestIsMultiLineIndicator_PipeWithSpace(t *testing.T) {
	assert.True(t, isMultiLineIndicator(" | "), "Pipe with spaces is multi-line indicator")
}

func TestIsMultiLineIndicator_GreaterThan(t *testing.T) {
	assert.True(t, isMultiLineIndicator(">"), "Greater than is multi-line indicator")
}

func TestIsMultiLineIndicator_PipePlus(t *testing.T) {
	assert.True(t, isMultiLineIndicator("|+"), "Pipe plus is multi-line indicator")
}

func TestIsMultiLineIndicator_GreaterMinus(t *testing.T) {
	assert.True(t, isMultiLineIndicator(">-"), "Greater minus is multi-line indicator")
}

func TestIsMultiLineIndicator_PipeMinus(t *testing.T) {
	assert.True(t, isMultiLineIndicator("|-"), "Pipe minus is multi-line indicator")
}

func TestIsMultiLineIndicator_GreaterPlus(t *testing.T) {
	assert.True(t, isMultiLineIndicator(">+"), "Greater plus is multi-line indicator")
}

func TestIsMultiLineIndicator_RegularValue(t *testing.T) {
	assert.False(t, isMultiLineIndicator("some value"), "Regular value is not multi-line")
}

// =============================================================================
// UNIT TESTS: detectBlockStart function
// =============================================================================

func TestDetectBlockStart_Rule(t *testing.T) {
	result := detectBlockStart("- rule: Test", 0, 0, 0, 0, false)
	assert.Equal(t, "rule", result, "Should detect rule block")
}

func TestDetectBlockStart_Macro(t *testing.T) {
	result := detectBlockStart("- macro: is_shell", 0, 0, 0, 0, false)
	assert.Equal(t, "macro", result, "Should detect macro block")
}

func TestDetectBlockStart_List(t *testing.T) {
	result := detectBlockStart("- list: binaries", 0, 0, 0, 0, false)
	assert.Equal(t, "list", result, "Should detect list block")
}

func TestDetectBlockStart_EngineVersion(t *testing.T) {
	result := detectBlockStart("- required_engine_version: 10", 0, 0, 0, 0, false)
	assert.Equal(t, "required_engine_version", result, "Should detect engine version block")
}

func TestDetectBlockStart_PluginVersions(t *testing.T) {
	result := detectBlockStart("- required_plugin_versions:", 0, 0, 0, 0, false)
	assert.Equal(t, "required_plugin_versions", result, "Should detect plugin versions block")
}

func TestDetectBlockStart_NotABlock(t *testing.T) {
	result := detectBlockStart("  condition: something", 0, 0, 0, 0, false)
	assert.Equal(t, "", result, "Should return empty for non-block line")
}
