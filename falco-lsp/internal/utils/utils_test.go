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

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSafeLine(t *testing.T) {
	tests := []struct {
		name string
		line int
		want int
	}{
		{"positive", 5, 5},
		{"zero", 0, 0},
		{"negative", -1, 0},
		{"very negative", -100, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, SafeLine(tt.line), "SafeLine(%d)", tt.line)
		})
	}
}

func TestSafeCharacter(t *testing.T) {
	tests := []struct {
		name string
		char int
		want int
	}{
		{"positive", 10, 10},
		{"zero", 0, 0},
		{"negative", -5, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, SafeCharacter(tt.char), "SafeCharacter(%d)", tt.char)
		})
	}
}

func TestSafeIndex(t *testing.T) {
	tests := []struct {
		name string
		idx  int
		max  int
		want int
	}{
		{"within range", 5, 10, 5},
		{"at zero", 0, 10, 0},
		{"at max-1", 9, 10, 9},
		{"negative", -1, 10, 0},
		{"above max", 15, 10, 9},
		{"zero max", 5, 0, 0},
		{"negative max", 5, -1, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, SafeIndex(tt.idx, tt.max), "SafeIndex(%d, %d)", tt.idx, tt.max)
		})
	}
}

func TestMatchesURI(t *testing.T) {
	tests := []struct {
		name string
		path string
		uri  string
		want bool
	}{
		{"exact match", "/path/to/file.yaml", "/path/to/file.yaml", true},
		{"with file prefix", "/path/to/file.yaml", "file:///path/to/file.yaml", true},
		{"no match", "/path/to/file.yaml", "/other/file.yaml", false},
		{"prefix no match", "/path/to/file.yaml", "file:///other/file.yaml", false},
		{"empty strings", "", "", true},
		{"empty path", "", "file:///some/path", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, MatchesURI(tt.path, tt.uri), "MatchesURI(%q, %q)", tt.path, tt.uri)
		})
	}
}

func TestJoinStrings(t *testing.T) {
	tests := []struct {
		name string
		strs []string
		sep  string
		want string
	}{
		{"empty", []string{}, ", ", ""},
		{"single", []string{"a"}, ", ", "a"},
		{"two", []string{"a", "b"}, ", ", "a, b"},
		{"three", []string{"a", "b", "c"}, "-", "a-b-c"},
		{"empty sep", []string{"a", "b"}, "", "ab"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, JoinStrings(tt.strs, tt.sep), "JoinStrings(%v, %q)", tt.strs, tt.sep)
		})
	}
}

func TestClampLineRange(t *testing.T) {
	tests := []struct {
		name       string
		start, end int
		length     int
		wantStart  int
		wantEnd    int
	}{
		{"normal", 5, 10, 20, 5, 10},
		{"negative start", -5, 10, 20, 0, 10},
		{"negative end", 5, -2, 20, 0, 0},
		{"start > length", 25, 30, 20, 20, 20},
		{"end > length", 5, 30, 20, 5, 20},
		{"start > end", 10, 5, 20, 5, 5},
		{"zero length", 5, 10, 0, 0, 0},
		{"negative length", 5, 10, -5, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStart, gotEnd := ClampLineRange(tt.start, tt.end, tt.length)
			assert.Equal(t, tt.wantStart, gotStart, "ClampLineRange(%d, %d, %d) start", tt.start, tt.end, tt.length)
			assert.Equal(t, tt.wantEnd, gotEnd, "ClampLineRange(%d, %d, %d) end", tt.start, tt.end, tt.length)
		})
	}
}
