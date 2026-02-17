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

package protocol

// ToLSPLine converts a 1-based line number (from parser) to a 0-based line index (for LSP).
// Returns 0 if the result would be negative.
func ToLSPLine(line int) int {
	return max(0, line-1)
}

// ToLSPPosition converts 1-based line and column to a 0-based LSP Position.
// Both line and column are converted from 1-based to 0-based.
// Returns Position{0, 0} if either would be negative.
func ToLSPPosition(line, column int) Position {
	return Position{
		Line:      max(0, line-1),
		Character: max(0, column-1),
	}
}

// NewPosition creates a new Position with the given 0-based line and character.
// Use this for values already in LSP 0-based format.
func NewPosition(line, character int) Position {
	return Position{
		Line:      max(0, line),
		Character: max(0, character),
	}
}

// NewRange creates a Range from start and end positions.
func NewRange(start, end Position) Range {
	return Range{Start: start, End: end}
}

// NewSingleLineRange creates a Range that spans a single line from startChar to endChar.
// lineIdx is 0-based (already in LSP format).
func NewSingleLineRange(lineIdx, startChar, endChar int) Range {
	lineIdx = max(0, lineIdx)
	startChar = max(0, startChar)
	endChar = max(0, endChar)
	return Range{
		Start: Position{Line: lineIdx, Character: startChar},
		End:   Position{Line: lineIdx, Character: endChar},
	}
}

// NewLocation creates a Location with the given URI and range.
func NewLocation(uri string, rng Range) Location {
	return Location{
		URI:   uri,
		Range: rng,
	}
}

// NewLocationPtr creates a pointer to a Location with the given URI and range.
// Useful for definition provider which returns *Location.
func NewLocationPtr(uri string, rng Range) *Location {
	loc := NewLocation(uri, rng)
	return &loc
}

// NewSymbolLocation creates a Location for a symbol definition.
// line is 1-based (from parser), converted to 0-based for LSP.
// charOffset is the 0-based character offset where the symbol name starts.
// nameLen is the length of the symbol name.
func NewSymbolLocation(uri string, line, charOffset, nameLen int) Location {
	lineIdx := ToLSPLine(line)
	return Location{
		URI:   uri,
		Range: NewSingleLineRange(lineIdx, charOffset, charOffset+nameLen),
	}
}

// NewSymbolLocationPtr creates a pointer to a Location for a symbol definition.
// line is 1-based (from parser), converted to 0-based for LSP.
// The range spans from character 0 to nameLen.
func NewSymbolLocationPtr(uri string, line, nameLen int) *Location {
	lineIdx := ToLSPLine(line)
	return &Location{
		URI:   uri,
		Range: NewSingleLineRange(lineIdx, 0, nameLen),
	}
}

// GetLineInfo extracts line information from a slice of lines.
// line is 1-based (from parser), converted to 0-based for LSP.
// Returns: lineIdx (0-based), lineContent, lineLen.
func GetLineInfo(lines []string, line int) (lineIdx int, lineContent string, lineLen int) {
	lineIdx = ToLSPLine(line)
	if lineIdx < len(lines) {
		lineContent = lines[lineIdx]
		lineLen = len(lineContent)
	}
	return lineIdx, lineContent, lineLen
}
