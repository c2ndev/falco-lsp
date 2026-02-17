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

package references

import (
	"strings"

	"github.com/falcosecurity/falco-lsp/internal/ast"
	"github.com/falcosecurity/falco-lsp/internal/condition"
	"github.com/falcosecurity/falco-lsp/internal/lsp/document"
	"github.com/falcosecurity/falco-lsp/internal/lsp/protocol"
	"github.com/falcosecurity/falco-lsp/internal/schema"
	"github.com/falcosecurity/falco-lsp/internal/utils"
)

// findWordInCondition finds occurrences of a word in a condition string using AST parsing.
// This provides precise positions and avoids false positives from substring matches.
func findWordInCondition(cond, word, file string, baseLine int) []protocol.Location {
	var locations []protocol.Location

	if cond == "" {
		return locations
	}

	// Parse the condition into an AST
	parseResult := condition.Parse(cond)
	if parseResult == nil || parseResult.Expression == nil {
		// Fallback to text-based search if parsing fails
		return findWordInConditionText(cond, word, file, baseLine)
	}

	uri := document.NormalizeURI(file)

	// Walk the AST to find macro and list references
	ast.Walk(parseResult.Expression, func(expr ast.Expression) bool {
		switch e := expr.(type) {
		case *ast.MacroRef:
			if e.Name == word {
				// AST lines are 1-based; baseLine is also 1-based, so combined offset needs adjustment
				startLine := utils.SafeLine(baseLine + e.Range.Start.Line - 1)
				endLine := utils.SafeLine(baseLine + e.Range.End.Line - 1)
				loc := protocol.NewLocation(uri, protocol.NewRange(
					protocol.NewPosition(startLine, e.Range.Start.Column),
					protocol.NewPosition(endLine, e.Range.End.Column),
				))
				locations = append(locations, loc)
			}
		case *ast.ListRef:
			if e.Name == word {
				startLine := utils.SafeLine(baseLine + e.Range.Start.Line - 1)
				endLine := utils.SafeLine(baseLine + e.Range.End.Line - 1)
				loc := protocol.NewLocation(uri, protocol.NewRange(
					protocol.NewPosition(startLine, e.Range.Start.Column),
					protocol.NewPosition(endLine, e.Range.End.Column),
				))
				locations = append(locations, loc)
			}
		}
		return true // Continue walking
	})

	return locations
}

// findWordInConditionText is the fallback text-based search when AST parsing fails.
func findWordInConditionText(cond, word, file string, baseLine int) []protocol.Location {
	var locations []protocol.Location
	uri := document.NormalizeURI(file)

	// Simple word boundary search
	// Look for the word surrounded by non-word characters
	idx := 0
	for {
		pos := strings.Index(cond[idx:], word)
		if pos == -1 {
			break
		}

		actualPos := idx + pos

		// Check word boundaries
		isWordStart := actualPos == 0 || !schema.IsIdentifierCharByte(cond[actualPos-1])
		isWordEnd := actualPos+len(word) >= len(cond) || !schema.IsIdentifierCharByte(cond[actualPos+len(word)])

		if isWordStart && isWordEnd {
			// Calculate line offset within condition (conditions can be multiline)
			lineOffset := 0
			charOffset := actualPos
			for i := 0; i < actualPos; i++ {
				if cond[i] == '\n' {
					lineOffset++
					charOffset = actualPos - i - 1
				}
			}

			line := baseLine + lineOffset
			rng := protocol.NewSingleLineRange(line, charOffset, charOffset+len(word))
			locations = append(locations, protocol.NewLocation(uri, rng))
		}

		idx = actualPos + 1
	}

	return locations
}
