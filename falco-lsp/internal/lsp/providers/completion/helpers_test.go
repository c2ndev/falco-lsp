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

// Package completion provides code completion functionality.
package completion

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/c2ndev/falco-lsp/internal/lsp/document"
)

// =============================================================================
// UNIT TESTS: applyIndentation function
// =============================================================================

func TestApplyIndentation_NoIndentation_SingleLine(t *testing.T) {
	result := applyIndentation("- rule: ${1:name}", "")
	assert.Equal(t, "- rule: ${1:name}", result, "No indentation should return text unchanged")
}

func TestApplyIndentation_NoIndentation_MultiLine(t *testing.T) {
	input := "- rule: ${1:name}\n  desc: ${2:description}"
	result := applyIndentation(input, "")
	assert.Equal(t, input, result, "No indentation should return multi-line text unchanged")
}

func TestApplyIndentation_WithSpaces_SingleLine(t *testing.T) {
	result := applyIndentation("- rule: ${1:name}", "  ")
	assert.Equal(t, "  - rule: ${1:name}", result, "Should add 2-space indentation to single line")
}

func TestApplyIndentation_WithSpaces_MultiLine(t *testing.T) {
	input := "- rule: ${1:name}\n  desc: ${2:description}"
	expected := "  - rule: ${1:name}\n    desc: ${2:description}"
	result := applyIndentation(input, "  ")
	assert.Equal(t, expected, result, "Should add 2-space indentation to all non-empty lines")
}

func TestApplyIndentation_WithTab_SingleLine(t *testing.T) {
	result := applyIndentation("- rule: ${1:name}", "\t")
	assert.Equal(t, "\t- rule: ${1:name}", result, "Should add tab indentation to single line")
}

func TestApplyIndentation_WithTab_MultiLine(t *testing.T) {
	input := "- rule: ${1:name}\n  desc: ${2:description}"
	expected := "\t- rule: ${1:name}\n\t  desc: ${2:description}"
	result := applyIndentation(input, "\t")
	assert.Equal(t, expected, result, "Should add tab indentation to all non-empty lines")
}

func TestApplyIndentation_PreservesEmptyLines(t *testing.T) {
	input := "- rule: ${1:name}\n\n  desc: ${2:description}"
	expected := "  - rule: ${1:name}\n\n    desc: ${2:description}"
	result := applyIndentation(input, "  ")
	assert.Equal(t, expected, result, "Should preserve empty lines without adding indentation")
}

func TestApplyIndentation_MixedIndentation(t *testing.T) {
	result := applyIndentation("- rule: ${1:name}", "  \t")
	assert.Equal(t, "  \t- rule: ${1:name}", result, "Should handle mixed space/tab indentation")
}

func TestApplyIndentation_FourSpaces_MultiLine(t *testing.T) {
	input := "- rule: ${1:name}\n  desc: ${2:description}\n  condition: ${3:cond}"
	expected := "    - rule: ${1:name}\n      desc: ${2:description}\n      condition: ${3:cond}"
	result := applyIndentation(input, "    ")
	assert.Equal(t, expected, result, "Should add 4-space indentation to all lines")
}

// =============================================================================
// UNIT TESTS: extractIndentation function
// =============================================================================

func TestExtractIndentation_Empty(t *testing.T) {
	indent := extractIndentation("")
	assert.Equal(t, "", indent, "Empty string should return empty indentation")
}

func TestExtractIndentation_NoIndent(t *testing.T) {
	indent := extractIndentation("hello world")
	assert.Equal(t, "", indent, "No leading whitespace should return empty")
}

func TestExtractIndentation_Spaces(t *testing.T) {
	indent := extractIndentation("  hello world")
	assert.Equal(t, "  ", indent, "Should extract leading spaces")
}

func TestExtractIndentation_Tabs(t *testing.T) {
	indent := extractIndentation("\t\thello world")
	assert.Equal(t, "\t\t", indent, "Should extract leading tabs")
}

func TestExtractIndentation_Mixed(t *testing.T) {
	indent := extractIndentation("  \thello world")
	assert.Equal(t, "  \t", indent, "Should extract mixed indentation")
}

func TestExtractIndentation_OnlyWhitespace(t *testing.T) {
	indent := extractIndentation("    ")
	assert.Equal(t, "    ", indent, "All whitespace should return full string")
}

// =============================================================================
// UNIT TESTS: isFieldPrefix function
// =============================================================================

func TestIsFieldPrefix_Empty(t *testing.T) {
	assert.False(t, isFieldPrefix(""), "Empty string is not a field prefix")
}

func TestIsFieldPrefix_WithDot(t *testing.T) {
	assert.True(t, isFieldPrefix("proc."), "String ending with dot is a field prefix")
}

func TestIsFieldPrefix_WithDotInMiddle(t *testing.T) {
	assert.True(t, isFieldPrefix("proc.name"), "String containing dot is a field prefix")
}

func TestIsFieldPrefix_WithBracket(t *testing.T) {
	assert.True(t, isFieldPrefix("evt.args["), "String with dot and bracket is a field prefix")
}

func TestIsFieldPrefix_NoDot(t *testing.T) {
	assert.False(t, isFieldPrefix("proc"), "String without dot is not a field prefix")
}

// =============================================================================
// UNIT TESTS: extractCurrentWord function
// =============================================================================

func TestExtractCurrentWord_ValidRange(t *testing.T) {
	line := "proc.name in"
	wordRange := document.WordRange{Start: 0, End: 4}
	result := extractCurrentWord(line, wordRange)
	assert.Equal(t, "proc", result, "Should extract word from valid range")
}

func TestExtractCurrentWord_MiddleOfLine(t *testing.T) {
	line := "proc.name in"
	wordRange := document.WordRange{Start: 5, End: 9}
	result := extractCurrentWord(line, wordRange)
	assert.Equal(t, "name", result, "Should extract word from middle of line")
}

func TestExtractCurrentWord_EndOfLine(t *testing.T) {
	line := "proc.name in"
	wordRange := document.WordRange{Start: 10, End: 12}
	result := extractCurrentWord(line, wordRange)
	assert.Equal(t, "in", result, "Should extract word at end of line")
}

func TestExtractCurrentWord_EmptyLine(t *testing.T) {
	line := ""
	wordRange := document.WordRange{Start: 0, End: 0}
	result := extractCurrentWord(line, wordRange)
	assert.Equal(t, "", result, "Should return empty for empty line")
}

func TestExtractCurrentWord_InvalidRange_NegativeStart(t *testing.T) {
	line := "proc.name"
	wordRange := document.WordRange{Start: -1, End: 4}
	result := extractCurrentWord(line, wordRange)
	assert.Equal(t, "", result, "Should return empty for negative start")
}

func TestExtractCurrentWord_InvalidRange_StartGreaterThanEnd(t *testing.T) {
	line := "proc.name"
	wordRange := document.WordRange{Start: 5, End: 3}
	result := extractCurrentWord(line, wordRange)
	assert.Equal(t, "", result, "Should return empty when start >= end")
}

func TestExtractCurrentWord_InvalidRange_EndExceedsLength(t *testing.T) {
	line := "proc"
	wordRange := document.WordRange{Start: 0, End: 10}
	result := extractCurrentWord(line, wordRange)
	assert.Equal(t, "", result, "Should return empty when end exceeds line length")
}

func TestExtractCurrentWord_FullLine(t *testing.T) {
	line := "condition"
	wordRange := document.WordRange{Start: 0, End: 9}
	result := extractCurrentWord(line, wordRange)
	assert.Equal(t, "condition", result, "Should extract full line as word")
}

// =============================================================================
// UNIT TESTS: detectCursorAfterWord function
// =============================================================================

func TestDetectCursorAfterWord_AtEndOfLine(t *testing.T) {
	line := "proc.name"
	char := 9
	wordRange := document.WordRange{Start: 0, End: 9}
	currentWord := "proc.name"
	result := detectCursorAfterWord(line, char, wordRange, currentWord)
	assert.True(t, result, "Should return true at end of line after word")
}

func TestDetectCursorAfterWord_AfterWordBeforeSpace(t *testing.T) {
	line := "proc.name "
	char := 9
	wordRange := document.WordRange{Start: 0, End: 9}
	currentWord := "proc.name"
	result := detectCursorAfterWord(line, char, wordRange, currentWord)
	assert.True(t, result, "Should return true when cursor is at word end followed by space")
}

func TestDetectCursorAfterWord_AfterWordBeforeOperator(t *testing.T) {
	line := "proc.name ="
	char := 9
	wordRange := document.WordRange{Start: 0, End: 9}
	currentWord := "proc.name"
	result := detectCursorAfterWord(line, char, wordRange, currentWord)
	assert.True(t, result, "Should return true when cursor is at word end followed by operator")
}

func TestDetectCursorAfterWord_MidWord(t *testing.T) {
	line := "proc.name"
	char := 5
	wordRange := document.WordRange{Start: 5, End: 9}
	currentWord := "name"
	result := detectCursorAfterWord(line, char, wordRange, currentWord)
	assert.False(t, result, "Should return false when cursor is not at word end")
}

func TestDetectCursorAfterWord_EmptyWord(t *testing.T) {
	line := "  "
	char := 0
	wordRange := document.WordRange{Start: 0, End: 0}
	currentWord := ""
	result := detectCursorAfterWord(line, char, wordRange, currentWord)
	assert.False(t, result, "Should return false for empty word")
}

func TestDetectCursorAfterWord_FollowedByWordChar(t *testing.T) {
	line := "proca"
	char := 4
	wordRange := document.WordRange{Start: 0, End: 4}
	currentWord := "proc"
	result := detectCursorAfterWord(line, char, wordRange, currentWord)
	assert.False(t, result, "Should return false when followed by word character")
}

func TestDetectCursorAfterWord_CharNotAtWordEnd(t *testing.T) {
	line := "proc.name"
	char := 5
	wordRange := document.WordRange{Start: 0, End: 9}
	currentWord := "proc.name"
	result := detectCursorAfterWord(line, char, wordRange, currentWord)
	assert.False(t, result, "Should return false when char is not at word end")
}
