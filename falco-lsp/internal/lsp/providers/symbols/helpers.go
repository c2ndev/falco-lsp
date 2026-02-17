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

package symbols

import (
	"strings"

	"github.com/falcosecurity/falco-lsp/internal/config"
	"github.com/falcosecurity/falco-lsp/internal/lsp/protocol"
	"github.com/falcosecurity/falco-lsp/internal/schema"
	"github.com/falcosecurity/falco-lsp/internal/utils"
)

// formatListDetail formats list items for display in symbol detail.
func formatListDetail(items []string) string {
	if len(items) == 0 {
		return ""
	}
	if len(items) <= config.ListPreviewItemsSymbol {
		return utils.JoinStrings(items, ", ")
	}
	return utils.JoinStrings(items[:config.ListPreviewItemsSymbol], ", ") + "..."
}

// findNameInLine finds the position of a name after a keyword in a line.
// Returns (start, end) character positions.
func findNameInLine(line, name, keyword string) (start, end int) {
	// Default fallback
	keywordLen := len(keyword) + 2 // "- keyword: " = keyword + 2 (for "- ")
	defaultStart := keywordLen + 1 // After the space
	defaultEnd := defaultStart + len(name)

	// Try to find the keyword in the line
	kwIdx := strings.Index(line, keyword)
	if kwIdx == -1 {
		return defaultStart, defaultEnd
	}

	// Find the name after the keyword
	afterKeyword := kwIdx + len(keyword)
	remaining := line[afterKeyword:]

	// Skip whitespace
	nameStart := afterKeyword
	for i, c := range remaining {
		if c != ' ' && c != '\t' {
			nameStart = afterKeyword + i
			break
		}
	}

	// The name extends for len(name) characters
	nameEnd := min(nameStart+len(name), len(line))

	return nameStart, nameEnd
}

// childPropertyInfo defines a property to look for in rule children.
type childPropertyInfo struct {
	name   schema.PropertyName
	prefix string // property name with colon suffix
}

// childProperties are the properties to extract as rule children.
var childProperties = []childPropertyInfo{
	{schema.PropCondition, schema.PropCondition.String() + ":"},
	{schema.PropOutput, schema.PropOutput.String() + ":"},
	{schema.PropPriority, schema.PropPriority.String() + ":"},
}

// newPropertySymbol creates a DocumentSymbol for a property line.
func newPropertySymbol(line string, lineIdx int, propName schema.PropertyName) *protocol.DocumentSymbol {
	name := propName.String()
	prefix := name + ":"
	start := strings.Index(line, prefix)
	if start == -1 {
		return nil
	}
	return &protocol.DocumentSymbol{
		Name: name,
		Kind: protocol.SymbolKindProperty,
		Range: protocol.Range{
			Start: protocol.Position{Line: lineIdx, Character: 0},
			End:   protocol.Position{Line: lineIdx, Character: len(line)},
		},
		SelectionRange: protocol.Range{
			Start: protocol.Position{Line: lineIdx, Character: start},
			End:   protocol.Position{Line: lineIdx, Character: start + len(name)},
		},
	}
}
