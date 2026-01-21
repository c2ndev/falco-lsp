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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestToLSPLine(t *testing.T) {
	tests := []struct {
		name     string
		line     int
		expected int
	}{
		{"line 1 becomes 0", 1, 0},
		{"line 5 becomes 4", 5, 4},
		{"line 0 becomes 0 (clamped)", 0, 0},
		{"negative line becomes 0 (clamped)", -5, 0},
		{"large line number", 1000, 999},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ToLSPLine(tt.line)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestToLSPPosition(t *testing.T) {
	tests := []struct {
		name     string
		line     int
		column   int
		expected Position
	}{
		{"normal position", 1, 1, Position{Line: 0, Character: 0}},
		{"line 5 col 10", 5, 10, Position{Line: 4, Character: 9}},
		{"zero line clamped", 0, 5, Position{Line: 0, Character: 4}},
		{"zero column clamped", 5, 0, Position{Line: 4, Character: 0}},
		{"both negative clamped", -1, -1, Position{Line: 0, Character: 0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ToLSPPosition(tt.line, tt.column)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestNewPosition(t *testing.T) {
	tests := []struct {
		name      string
		line      int
		character int
		expected  Position
	}{
		{"normal position", 5, 10, Position{Line: 5, Character: 10}},
		{"zero position", 0, 0, Position{Line: 0, Character: 0}},
		{"negative line clamped", -1, 5, Position{Line: 0, Character: 5}},
		{"negative character clamped", 5, -1, Position{Line: 5, Character: 0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewPosition(tt.line, tt.character)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestNewRange(t *testing.T) {
	start := Position{Line: 1, Character: 5}
	end := Position{Line: 1, Character: 15}

	result := NewRange(start, end)

	require.Equal(t, start, result.Start)
	require.Equal(t, end, result.End)
}

func TestNewSingleLineRange(t *testing.T) {
	tests := []struct {
		name      string
		lineIdx   int
		startChar int
		endChar   int
		expected  Range
	}{
		{
			"normal range",
			5, 10, 20,
			Range{Start: Position{Line: 5, Character: 10}, End: Position{Line: 5, Character: 20}},
		},
		{
			"zero values",
			0, 0, 5,
			Range{Start: Position{Line: 0, Character: 0}, End: Position{Line: 0, Character: 5}},
		},
		{
			"negative values clamped",
			-1, -5, 10,
			Range{Start: Position{Line: 0, Character: 0}, End: Position{Line: 0, Character: 10}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewSingleLineRange(tt.lineIdx, tt.startChar, tt.endChar)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestNewLocation(t *testing.T) {
	uri := "file:///test.yaml"
	rng := Range{Start: Position{Line: 5, Character: 0}, End: Position{Line: 5, Character: 10}}

	result := NewLocation(uri, rng)

	require.Equal(t, uri, result.URI)
	require.Equal(t, rng, result.Range)
}

func TestNewSymbolLocation(t *testing.T) {
	tests := []struct {
		name       string
		uri        string
		line       int
		charOffset int
		nameLen    int
		expected   Location
	}{
		{
			"macro at line 5",
			"file:///test.yaml",
			5, 9, 10,
			Location{
				URI: "file:///test.yaml",
				Range: Range{
					Start: Position{Line: 4, Character: 9},
					End:   Position{Line: 4, Character: 19},
				},
			},
		},
		{
			"list at line 1",
			"file:///rules.yaml",
			1, 8, 5,
			Location{
				URI: "file:///rules.yaml",
				Range: Range{
					Start: Position{Line: 0, Character: 8},
					End:   Position{Line: 0, Character: 13},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewSymbolLocation(tt.uri, tt.line, tt.charOffset, tt.nameLen)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestNewSymbolLocationPtr(t *testing.T) {
	uri := "file:///test.yaml"
	line := 10
	nameLen := 15

	result := NewSymbolLocationPtr(uri, line, nameLen)

	require.NotNil(t, result)
	require.Equal(t, uri, result.URI)
	require.Equal(t, 9, result.Range.Start.Line) // 10-1 = 9
	require.Equal(t, 0, result.Range.Start.Character)
	require.Equal(t, 9, result.Range.End.Line)
	require.Equal(t, 15, result.Range.End.Character)
}

func TestGetLineInfo(t *testing.T) {
	lines := []string{
		"- rule: test_rule",
		"  condition: spawned_process",
		"  output: test output",
	}

	tests := []struct {
		name            string
		line            int
		expectedIdx     int
		expectedContent string
		expectedLen     int
	}{
		{"line 1", 1, 0, "- rule: test_rule", 17},
		{"line 2", 2, 1, "  condition: spawned_process", 28},
		{"line 3", 3, 2, "  output: test output", 21},
		{"line 0 clamped", 0, 0, "- rule: test_rule", 17},
		{"line beyond bounds", 10, 9, "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx, content, length := GetLineInfo(lines, tt.line)
			require.Equal(t, tt.expectedIdx, idx)
			require.Equal(t, tt.expectedContent, content)
			require.Equal(t, tt.expectedLen, length)
		})
	}
}

func TestGetLineInfo_EmptyLines(t *testing.T) {
	var lines []string

	idx, content, length := GetLineInfo(lines, 1)

	require.Equal(t, 0, idx)
	require.Equal(t, "", content)
	require.Equal(t, 0, length)
}
