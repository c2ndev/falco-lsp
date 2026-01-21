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

	"github.com/c2ndev/falco-lsp/internal/schema"
)

// Context stack identifiers for formatting.
const (
	ctxExceptions             = "exceptions"
	ctxExceptionValues        = "exception_values"
	ctxRequiredPluginVersions = "required_plugin_versions"
	ctxAlternatives           = "alternatives"
	ctxExceptionItem          = "exception_item"
	ctxPluginVersionItem      = "plugin_version_item"
	ctxAlternativeItem        = "alternative_item"
	ctxOverride               = "override"
)

// Property key constants used in formatting logic.
const (
	propKeyName         = "name"
	propKeyVersion      = "version"
	propKeyAlternatives = "alternatives"
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

// formatContext tracks the current formatting context using a stack-based approach.
type formatContext struct {
	stack       []string // stack of context: ["rule", "exceptions", "exception_item", "values"]
	inMultiLine bool     // inside a multi-line block (| or >)
}

func (ctx *formatContext) push(s string) {
	ctx.stack = append(ctx.stack, s)
}

func (ctx *formatContext) pop() {
	if len(ctx.stack) > 0 {
		ctx.stack = ctx.stack[:len(ctx.stack)-1]
	}
}

func (ctx *formatContext) popTo(s string) {
	// Pop until we find s, then pop s too
	for len(ctx.stack) > 0 {
		top := ctx.stack[len(ctx.stack)-1]
		ctx.stack = ctx.stack[:len(ctx.stack)-1]
		if top == s {
			break
		}
	}
}

func (ctx *formatContext) current() string {
	if len(ctx.stack) == 0 {
		return ""
	}
	return ctx.stack[len(ctx.stack)-1]
}

func (ctx *formatContext) depth() int {
	return len(ctx.stack)
}

func (ctx *formatContext) reset() {
	ctx.stack = nil
	ctx.inMultiLine = false
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
	indent := strings.Repeat(" ", opts.TabSize)
	if !opts.InsertSpaces {
		indent = "\t"
	}

	prevLineBlank := false
	ctx := &formatContext{}

	for _, line := range lines {
		formatted := formatLineStateful(line, indent, opts, ctx)

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

// formatLineStateful formats a single line using schema-based context tracking.
func formatLineStateful(line, indent string, opts Options, ctx *formatContext) string {
	// Trim trailing whitespace
	if opts.TrimTrailingWhitespace {
		line = strings.TrimRight(line, " \t")
	}

	// Get trimmed content
	trimmed := strings.TrimLeft(line, " \t")
	if trimmed == "" {
		ctx.inMultiLine = false
		return ""
	}

	// If in multi-line block, preserve content as-is
	if ctx.inMultiLine {
		if isPropertyKey(trimmed) || isTopLevelItem(trimmed) || strings.HasPrefix(trimmed, "- ") {
			ctx.inMultiLine = false
		} else {
			return line
		}
	}

	// Check if we're starting a multi-line block
	if strings.HasSuffix(trimmed, "|") || strings.HasSuffix(trimmed, ">") ||
		strings.HasSuffix(trimmed, "|-") || strings.HasSuffix(trimmed, ">-") {
		ctx.inMultiLine = true
	}

	// Top-level YAML list items (rules, macros, lists)
	if isTopLevelItem(trimmed) {
		ctx.reset()
		blockType := getTopLevelBlockType(trimmed)
		ctx.push(blockType)
		return trimmed // Level 0
	}

	// Comments - preserve relative indentation
	if strings.HasPrefix(trimmed, "#") {
		return line
	}

	key := getPropertyKey(trimmed)

	// Handle list items (- ...)
	if strings.HasPrefix(trimmed, "- ") {
		return formatListItem(trimmed, indent, ctx)
	}

	// Handle property keys
	if key != "" {
		return formatProperty(key, trimmed, indent, ctx)
	}

	// Default: preserve with calculated indent
	if ctx.depth() > 0 {
		return strings.Repeat(indent, ctx.depth()) + trimmed
	}
	return line
}

// formatListItem formats a YAML list item based on context.
func formatListItem(trimmed, indent string, ctx *formatContext) string {
	current := ctx.current()

	switch current {
	case ctxExceptions:
		// Exception list item: - name: ...
		ctx.push(ctxExceptionItem)
		return strings.Repeat(indent, 2) + trimmed // Level 2

	case ctxExceptionValues:
		// Value inside exception values: - [value]
		return strings.Repeat(indent, 4) + trimmed // Level 4

	case ctxRequiredPluginVersions:
		// Plugin version list item
		ctx.push(ctxPluginVersionItem)
		return strings.Repeat(indent, 2) + trimmed // Level 2

	case ctxAlternatives:
		// Alternative plugin item
		ctx.push(ctxAlternativeItem)
		return strings.Repeat(indent, 4) + trimmed // Level 4

	case "items", "tags":
		// List items under items: or tags: (when expanded)
		return strings.Repeat(indent, 2) + trimmed // Level 2

	default:
		// Generic list item at current depth
		depth := ctx.depth()
		if depth == 0 {
			depth = 1
		}
		return strings.Repeat(indent, depth) + trimmed
	}
}

// formatProperty formats a YAML property based on schema context.
func formatProperty(key, trimmed, indent string, ctx *formatContext) string {
	current := ctx.current()

	// Check if this property exits the current context
	if shouldExitContext(key, current) {
		exitContext(key, ctx)
		current = ctx.current()
	}

	// Determine indent level based on schema
	switch current {
	case schema.BlockRule.String(), schema.BlockMacro.String(), schema.BlockList.String():
		// Properties of rule/macro/list
		if isNestedBlockProperty(key) {
			ctx.push(key) // Enter nested context (exceptions, override, etc.)
		}
		return indent + trimmed // Level 1

	case "exception_item":
		// Properties inside an exception (name, fields, comps, values)
		if isExceptionProperty(key) {
			if key == schema.PropExceptionValues.String() {
				ctx.push(ctxExceptionValues)
			}
			return strings.Repeat(indent, 3) + trimmed // Level 3
		}
		// Not an exception property, exit to rule level
		ctx.popTo(ctxExceptionItem)
		ctx.pop() // Also pop "exceptions"
		if isNestedBlockProperty(key) {
			ctx.push(key)
		}
		return indent + trimmed // Level 1

	case ctxPluginVersionItem:
		// Properties inside plugin version (name, version, alternatives)
		if isPluginVersionProperty(key) {
			if key == propKeyAlternatives {
				ctx.push(ctxAlternatives)
			}
			return strings.Repeat(indent, 3) + trimmed // Level 3
		}
		ctx.popTo(ctxPluginVersionItem)
		return indent + trimmed // Level 1

	case ctxAlternativeItem:
		// Properties inside alternative (name, version)
		if isAlternativeProperty(key) {
			return strings.Repeat(indent, 5) + trimmed // Level 5
		}
		ctx.popTo(ctxAlternativeItem)
		return strings.Repeat(indent, 3) + trimmed

	case ctxOverride:
		// Override properties
		if isOverrideProperty(key) {
			return strings.Repeat(indent, 2) + trimmed // Level 2
		}
		ctx.pop() // Exit override
		if isNestedBlockProperty(key) {
			ctx.push(key)
		}
		return indent + trimmed // Level 1

	case ctxExceptions, ctxRequiredPluginVersions:
		// Waiting for list items, shouldn't have properties directly
		return strings.Repeat(indent, 2) + trimmed // Level 2

	default:
		// Fallback
		depth := ctx.depth()
		if depth == 0 {
			depth = 1
		}
		return strings.Repeat(indent, depth) + trimmed
	}
}

// shouldExitContext determines if we should exit the current context.
func shouldExitContext(key, current string) bool {
	switch current {
	case ctxExceptionItem:
		return !isExceptionProperty(key)
	case ctxPluginVersionItem:
		return !isPluginVersionProperty(key)
	case ctxAlternativeItem:
		return !isAlternativeProperty(key)
	case ctxOverride:
		return !isOverrideProperty(key)
	case ctxExceptionValues:
		return true // Properties exit values context
	}
	return false
}

// exitContext exits the current context appropriately.
func exitContext(key string, ctx *formatContext) {
	current := ctx.current()
	switch current {
	case ctxExceptionValues:
		ctx.pop() // Pop exception_values
		if !isExceptionProperty(key) {
			ctx.pop() // Pop exception_item
			if ctx.current() == ctxExceptions {
				ctx.pop() // Pop exceptions
			}
		}
	case ctxExceptionItem:
		ctx.pop() // Pop exception_item
		if ctx.current() == ctxExceptions {
			ctx.pop() // Pop exceptions
		}
	case ctxOverride:
		ctx.pop()
	case ctxPluginVersionItem:
		ctx.pop()
		if ctx.current() == ctxRequiredPluginVersions {
			ctx.pop()
		}
	case ctxAlternativeItem:
		ctx.pop()
		if ctx.current() == ctxAlternatives {
			ctx.pop()
		}
	}
}

// Schema-based property checks using the schema package

func isNestedBlockProperty(key string) bool {
	switch schema.PropertyName(key) {
	case schema.PropExceptions, schema.PropOverride:
		return true
	default:
		// required_plugin_versions is handled at top level
		return key == ctxRequiredPluginVersions
	}
}

func isExceptionProperty(key string) bool {
	for _, p := range schema.ExceptionProperties {
		if p.Name.String() == key {
			return true
		}
	}
	return false
}

func isOverrideProperty(key string) bool {
	for _, p := range schema.OverrideableProperties {
		if p.Name.String() == key {
			return true
		}
	}
	return false
}

func isPluginVersionProperty(key string) bool {
	return key == propKeyName || key == propKeyVersion || key == propKeyAlternatives
}

func isAlternativeProperty(key string) bool {
	return key == propKeyName || key == propKeyVersion
}

// getPropertyKey extracts the key from a "key: value" line.
func getPropertyKey(trimmed string) string {
	if strings.HasPrefix(trimmed, "- ") {
		return "" // List item, not a property
	}
	colonIndex := strings.Index(trimmed, ":")
	if colonIndex > 0 {
		key := trimmed[:colonIndex]
		if isValidYAMLKey(key) {
			return key
		}
	}
	return ""
}

// isTopLevelItem returns true if the line starts a top-level Falco item.
func isTopLevelItem(trimmed string) bool {
	for _, bt := range schema.AllBlockTypes() {
		if strings.HasPrefix(trimmed, "- "+bt.String()+":") {
			return true
		}
	}
	// Also check version requirements
	if strings.HasPrefix(trimmed, "- "+schema.PropRequiredEngineVersion.String()+":") ||
		strings.HasPrefix(trimmed, "- "+schema.PropRequiredPluginVersions.String()+":") {
		return true
	}
	return false
}

// getTopLevelBlockType extracts the block type from a top-level line.
func getTopLevelBlockType(trimmed string) string {
	for _, bt := range schema.AllBlockTypes() {
		if strings.HasPrefix(trimmed, "- "+bt.String()+":") {
			return bt.String()
		}
	}
	if strings.HasPrefix(trimmed, "- "+schema.PropRequiredPluginVersions.String()+":") {
		return "required_plugin_versions"
	}
	if strings.HasPrefix(trimmed, "- "+schema.PropRequiredEngineVersion.String()+":") {
		return "required_engine_version"
	}
	return ""
}

// isPropertyKey returns true if the line is a YAML property key.
func isPropertyKey(trimmed string) bool {
	return getPropertyKey(trimmed) != ""
}

// validYAMLKeyRegex is pre-compiled for performance since isValidYAMLKey is called per-line.
var validYAMLKeyRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]*$`)

// isValidYAMLKey checks if a string is a valid YAML key.
func isValidYAMLKey(key string) bool {
	return validYAMLKeyRegex.MatchString(key)
}

// IsFormatted checks if content is already properly formatted.
func IsFormatted(content string, opts Options) bool {
	formatted := Format(content, opts)
	return content == formatted
}
