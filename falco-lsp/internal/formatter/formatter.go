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

package formatter

import (
	"regexp"
	"strings"
)

// Options contains formatting options.
type Options struct {
	// TabSize is the number of spaces for indentation (default: 2).
	TabSize int

	// InsertSpaces uses spaces instead of tabs (default: true).
	InsertSpaces bool

	// TrimTrailingWhitespace removes trailing whitespace (default: true).
	TrimTrailingWhitespace bool

	// InsertFinalNewline ensures file ends with newline (default: true).
	InsertFinalNewline bool

	// NormalizeBlankLines reduces multiple blank lines to one (default: true).
	NormalizeBlankLines bool
}

// DefaultOptions returns default formatting options.
func DefaultOptions() Options {
	return Options{
		TabSize:                2,
		InsertSpaces:           true,
		TrimTrailingWhitespace: true,
		InsertFinalNewline:     true,
		NormalizeBlankLines:    true,
	}
}

// Format formats Falco YAML content with the given options.
func Format(content string, opts Options) string {
	if content == "" {
		return ""
	}

	// Normalize line endings to LF
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")

	lines := strings.Split(content, "\n")
	var result []string

	// Determine indentation string
	indent := "  "
	if opts.TabSize > 0 {
		if opts.InsertSpaces {
			indent = strings.Repeat(" ", opts.TabSize)
		} else {
			indent = "\t"
		}
	}

	prevLineBlank := false
	for _, line := range lines {
		formatted := formatLine(line, indent, opts)

		// Handle multiple blank lines
		isBlank := strings.TrimSpace(formatted) == ""
		if opts.NormalizeBlankLines && isBlank && prevLineBlank {
			continue // Skip consecutive blank lines
		}

		result = append(result, formatted)
		prevLineBlank = isBlank
	}

	formatted := strings.Join(result, "\n")

	// Handle final newline
	if opts.InsertFinalNewline && !strings.HasSuffix(formatted, "\n") {
		formatted += "\n"
	}

	return formatted
}

// formatLine formats a single line.
func formatLine(line, indent string, opts Options) string {
	// Trim trailing whitespace
	if opts.TrimTrailingWhitespace {
		line = strings.TrimRight(line, " \t")
	}

	// Empty lines after trim
	trimmed := strings.TrimLeft(line, " \t")
	if trimmed == "" {
		return ""
	}

	// Convert tabs to spaces in leading whitespace
	if opts.InsertSpaces && strings.HasPrefix(line, "\t") {
		leadingTabs := 0
		for _, c := range line {
			if c == '\t' {
				leadingTabs++
			} else {
				break
			}
		}
		line = strings.Repeat(indent, leadingTabs) + line[leadingTabs:]
	}

	// Normalize property indentation
	trimmed = strings.TrimLeft(line, " \t")

	// Top-level YAML list items (rules, macros, lists)
	if isTopLevelItem(trimmed) {
		return trimmed
	}

	// Comments - preserve relative indentation
	if strings.HasPrefix(trimmed, "#") {
		return line
	}

	// Properties inside items should be indented
	if isPropertyKey(trimmed) {
		currentIndent := len(line) - len(trimmed)
		if currentIndent == 0 {
			// Property at column 0 should be indented
			return indent + trimmed
		}
		// Normalize to standard indent
		indentLevel := (currentIndent + len(indent) - 1) / len(indent)
		return strings.Repeat(indent, indentLevel) + trimmed
	}

	return line
}

// isTopLevelItem returns true if the line starts a top-level Falco item.
func isTopLevelItem(trimmed string) bool {
	patterns := []string{
		"- rule:",
		"- macro:",
		"- list:",
		"- required_engine_version:",
		"- required_plugin_versions:",
	}
	for _, p := range patterns {
		if strings.HasPrefix(trimmed, p) {
			return true
		}
	}
	return false
}

// isPropertyKey returns true if the line is a YAML property key.
func isPropertyKey(trimmed string) bool {
	// Matches patterns like "key:" or "key: value"
	if strings.HasPrefix(trimmed, "- ") {
		return false // List item
	}
	colonIndex := strings.Index(trimmed, ":")
	if colonIndex > 0 {
		key := trimmed[:colonIndex]
		return isValidYAMLKey(key)
	}
	return false
}

// isValidYAMLKey checks if a string is a valid YAML key.
func isValidYAMLKey(key string) bool {
	// YAML keys should be alphanumeric with underscores
	match, _ := regexp.MatchString(`^[a-zA-Z_][a-zA-Z0-9_]*$`, key)
	return match
}

// IsFormatted checks if content is already properly formatted.
func IsFormatted(content string, opts Options) bool {
	formatted := Format(content, opts)
	return content == formatted
}
