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

package utils

import "strings"

// SafeLine returns a non-negative line index.
// If line is negative, it returns 0.
func SafeLine(line int) int {
	if line < 0 {
		return 0
	}
	return line
}

// SafeCharacter returns a non-negative character index.
// If char is negative, it returns 0.
func SafeCharacter(char int) int {
	if char < 0 {
		return 0
	}
	return char
}

// SafeIndex returns a bounded index within [0, maxVal).
// If idx is negative, returns 0. If idx >= maxVal, returns maxVal-1 (or 0 if maxVal <= 0).
func SafeIndex(idx, maxVal int) int {
	if maxVal <= 0 {
		return 0
	}
	if idx < 0 {
		return 0
	}
	if idx >= maxVal {
		return maxVal - 1
	}
	return idx
}

// MatchesURI checks if a file path matches a document URI.
// Handles file:// prefix normalization.
func MatchesURI(path, uri string) bool {
	// Handle exact match
	if path == uri {
		return true
	}

	// Strip file:// prefix for comparison
	uriPath := uri
	if strings.HasPrefix(uri, "file://") {
		uriPath = uri[7:]
	}

	return path == uriPath
}

// JoinStrings joins strings with a separator.
// More efficient than strings.Join for small slices in hot paths.
func JoinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	if len(strs) == 1 {
		return strs[0]
	}

	// Calculate total length for pre-allocation
	n := len(sep) * (len(strs) - 1)
	for _, s := range strs {
		n += len(s)
	}

	var b strings.Builder
	b.Grow(n)
	b.WriteString(strs[0])
	for _, s := range strs[1:] {
		b.WriteString(sep)
		b.WriteString(s)
	}
	return b.String()
}

// ClampLineRange ensures start and end line indices are valid for a slice of given length.
// Returns (clampedStart, clampedEnd) where 0 <= clampedStart <= clampedEnd <= length.
func ClampLineRange(start, end, length int) (clampedStart, clampedEnd int) {
	if length <= 0 {
		return 0, 0
	}
	if start < 0 {
		start = 0
	}
	if end < 0 {
		end = 0
	}
	if start > length {
		start = length
	}
	if end > length {
		end = length
	}
	if start > end {
		start = end
	}
	return start, end
}
