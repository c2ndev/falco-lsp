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

package symbols

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/c2ndev/falco-lsp/internal/config"
	"github.com/c2ndev/falco-lsp/internal/lsp/protocol"
	"github.com/c2ndev/falco-lsp/internal/schema"
)

func TestFormatListDetail(t *testing.T) {
	tests := []struct {
		name     string
		items    []string
		expected string
	}{
		{
			name:     "empty list",
			items:    []string{},
			expected: "",
		},
		{
			name:     "nil list",
			items:    nil,
			expected: "",
		},
		{
			name:     "single item",
			items:    []string{"bash"},
			expected: "bash",
		},
		{
			name:     "two items",
			items:    []string{"bash", "sh"},
			expected: "bash, sh",
		},
		{
			name:     "exactly max items",
			items:    makeItems(config.ListPreviewItemsSymbol),
			expected: joinItems(makeItems(config.ListPreviewItemsSymbol)),
		},
		{
			name:     "more than max items",
			items:    makeItems(config.ListPreviewItemsSymbol + 2),
			expected: joinItems(makeItems(config.ListPreviewItemsSymbol)) + "...",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := formatListDetail(tc.items)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestFindNameInLine(t *testing.T) {
	tests := []struct {
		name         string
		line         string
		symbolName   string
		keyword      string
		wantStart    int
		wantEnd      int
		checkInRange bool // just verify the range is reasonable
	}{
		{
			name:       "rule definition",
			line:       "- rule: My Rule Name",
			symbolName: "My Rule Name",
			keyword:    "rule:",
			wantStart:  8,
			wantEnd:    20,
		},
		{
			name:       "macro definition",
			line:       "- macro: test_macro",
			symbolName: "test_macro",
			keyword:    "macro:",
			wantStart:  9,
			wantEnd:    19,
		},
		{
			name:       "list definition",
			line:       "- list: my_list",
			symbolName: "my_list",
			keyword:    "list:",
			wantStart:  8,
			wantEnd:    15,
		},
		{
			name:       "keyword not found",
			line:       "  desc: something",
			symbolName: "something",
			keyword:    "rule:",
			wantStart:  8,  // fallback
			wantEnd:    17, // fallback
		},
		{
			name:       "extra whitespace",
			line:       "- rule:   Spaced Name",
			symbolName: "Spaced Name",
			keyword:    "rule:",
			wantStart:  10,
			wantEnd:    21,
		},
		{
			name:       "tab separator",
			line:       "- rule:\tTabbed Name",
			symbolName: "Tabbed Name",
			keyword:    "rule:",
			wantStart:  8,
			wantEnd:    19,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			start, end := findNameInLine(tc.line, tc.symbolName, tc.keyword)
			assert.Equal(t, tc.wantStart, start, "start position mismatch")
			assert.Equal(t, tc.wantEnd, end, "end position mismatch")
		})
	}
}

func TestChildProperties(t *testing.T) {
	// Verify childProperties is properly initialized
	assert.NotEmpty(t, childProperties, "childProperties should not be empty")

	// Verify expected properties are present
	expectedProps := []schema.PropertyName{schema.PropCondition, schema.PropOutput, schema.PropPriority}
	for _, expected := range expectedProps {
		found := false
		for _, prop := range childProperties {
			if prop.name == expected {
				found = true
				assert.Equal(t, expected.String()+":", prop.prefix, "prefix should match property name + colon")
				break
			}
		}
		assert.True(t, found, "expected property %s not found in childProperties", expected)
	}
}

func TestNewPropertySymbol(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		lineIdx  int
		propName schema.PropertyName
		wantNil  bool
	}{
		{
			name:     "condition property",
			line:     "  condition: evt.type = execve",
			lineIdx:  5,
			propName: schema.PropCondition,
			wantNil:  false,
		},
		{
			name:     "output property",
			line:     "  output: Shell spawned",
			lineIdx:  6,
			propName: schema.PropOutput,
			wantNil:  false,
		},
		{
			name:     "priority property",
			line:     "  priority: WARNING",
			lineIdx:  7,
			propName: schema.PropPriority,
			wantNil:  false,
		},
		{
			name:     "property not in line",
			line:     "  desc: Some description",
			lineIdx:  3,
			propName: schema.PropCondition,
			wantNil:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sym := newPropertySymbol(tc.line, tc.lineIdx, tc.propName)

			if tc.wantNil {
				assert.Nil(t, sym, "expected nil symbol")
				return
			}

			assert.NotNil(t, sym, "expected non-nil symbol")
			assert.Equal(t, tc.propName.String(), sym.Name, "symbol name mismatch")
			assert.Equal(t, protocol.SymbolKindProperty, sym.Kind, "symbol kind mismatch")
			assert.Equal(t, tc.lineIdx, sym.Range.Start.Line, "range start line mismatch")
			assert.Equal(t, tc.lineIdx, sym.Range.End.Line, "range end line mismatch")
			assert.Equal(t, 0, sym.Range.Start.Character, "range should start at column 0")
			assert.Equal(t, len(tc.line), sym.Range.End.Character, "range should end at line length")
		})
	}
}

// makeItems creates a slice of single-character strings for testing.
func makeItems(count int) []string {
	items := make([]string, count)
	for i := range count {
		items[i] = string(rune('a' + i%26))
	}
	return items
}

func joinItems(items []string) string {
	if len(items) == 0 {
		return ""
	}
	result := items[0]
	for i := 1; i < len(items); i++ {
		result += ", " + items[i]
	}
	return result
}
