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

package protocol

import (
	"strings"
	"unicode/utf8"
)

// PositionToOffset converts a Position to a byte offset in the content.
func PositionToOffset(content string, pos Position) int {
	lines := strings.Split(content, "\n")
	offset := 0

	for i := 0; i < pos.Line && i < len(lines); i++ {
		offset += len(lines[i]) + 1 // +1 for newline
	}

	if pos.Line < len(lines) {
		lineLen := len(lines[pos.Line])
		if pos.Character < lineLen {
			offset += pos.Character
		} else {
			offset += lineLen
		}
	}

	return offset
}

// OffsetToPosition converts a byte offset to a Position.
func OffsetToPosition(content string, offset int) Position {
	if offset < 0 {
		return Position{Line: 0, Character: 0}
	}

	line := 0
	col := 0
	currentOffset := 0

	for i, r := range content {
		if i >= offset {
			break
		}
		if r == '\n' {
			line++
			col = 0
		} else {
			col++
		}
		currentOffset = i + utf8.RuneLen(r)
	}

	// If offset is beyond content, return end position
	if offset > currentOffset {
		return Position{Line: line, Character: col}
	}

	return Position{Line: line, Character: col}
}

// LineCount returns the number of lines in the content.
func LineCount(content string) int {
	if content == "" {
		return 0
	}
	return strings.Count(content, "\n") + 1
}

// GetLine returns the line at the given index (0-based).
func GetLine(content string, line int) string {
	lines := strings.Split(content, "\n")
	if line < 0 || line >= len(lines) {
		return ""
	}
	return lines[line]
}

// GetLines returns all lines in the content.
func GetLines(content string) []string {
	return strings.Split(content, "\n")
}
