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

package completion

import (
	"strings"

	"github.com/falcosecurity/falco-lsp/internal/config"
	"github.com/falcosecurity/falco-lsp/internal/schema"
)

// =============================================================================
// Types
// =============================================================================

// SemanticContext holds the semantic context for completion.
type SemanticContext struct {
	BlockContext    string
	PropertyContext string
	IndentLevel     int
	InMultiLine     bool
}

// blockScanResult holds the result of scanning for block context.
type blockScanResult struct {
	blockContext     string
	propertyName     string
	inMultiLine      bool
	inExceptionBlock bool
}

// =============================================================================
// Context Detection
// =============================================================================

// getSemanticContext analyzes the document to determine semantic context.
func getSemanticContext(lines []string, currentLine int) SemanticContext {
	ctx := SemanticContext{
		BlockContext:    schema.BlockTop.String(),
		PropertyContext: "",
		IndentLevel:     0,
		InMultiLine:     false,
	}

	if currentLine < 0 {
		return ctx
	}

	currentLineText := ""
	if currentLine < len(lines) {
		currentLineText = lines[currentLine]
	}
	ctx.IndentLevel = countIndent(currentLineText)
	trimmedLine := strings.TrimSpace(currentLineText)

	// At indent 0, we're at top-level context (starting a new block or typing block keywords)
	// This handles both "- rule:" (with dash) and "r" (without dash, user typing)
	if ctx.IndentLevel == 0 && trimmedLine != "" {
		return ctx
	}

	scanFromLine := currentLine
	if scanFromLine >= len(lines) {
		scanFromLine = len(lines) - 1
	}
	if scanFromLine < 0 {
		return ctx
	}

	isEmptyLine := trimmedLine == ""

	// Scan backwards to find block and property context
	scanResult := scanBlockContext(lines, scanFromLine, ctx.IndentLevel, isEmptyLine)
	ctx.BlockContext = scanResult.blockContext
	ctx.InMultiLine = scanResult.inMultiLine

	// If at indent 0 with non-empty content and no block found, treat as top-level
	if ctx.IndentLevel == 0 && !isEmptyLine && ctx.BlockContext == schema.BlockTop.String() {
		return ctx
	}

	// Only inherit property context from previous line if we're NOT on an empty line
	// starting a new property. On an empty line at the right indentation, we want to
	// show property completions for the current block, not values for a previous property.
	if scanResult.propertyName != "" && !isEmptyLine {
		ctx.PropertyContext = resolvePropertyContext(scanResult.propertyName, scanResult.inExceptionBlock)
	}

	if propCtx := checkCurrentLineProperty(currentLineText); propCtx != "" {
		ctx.PropertyContext = propCtx
	}

	return ctx
}

// scanBlockContext scans backwards through lines to find block context.
func scanBlockContext(lines []string, currentLine, indentLevel int, isEmptyLine bool) blockScanResult {
	result := blockScanResult{blockContext: schema.BlockTop.String()}
	var propertyLine = -1
	var exceptionItemLine = -1 // Track if we found a "- name:" line (exception item start)

	for i := currentLine; i >= 0; i-- {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		indent := countIndent(line)

		if trimmed == "" {
			continue
		}

		// Track potential exception item starts (- name:)
		if strings.HasPrefix(trimmed, "- name:") && exceptionItemLine == -1 {
			exceptionItemLine = i
		}

		// Check if we're in an exceptions block
		if strings.HasPrefix(trimmed, "exceptions:") && !result.inExceptionBlock {
			result.inExceptionBlock = true
			// Now check if the exception item we found earlier is actually inside this exceptions block
			if exceptionItemLine != -1 {
				// Verify the exception item is at higher indent than exceptions:
				exceptionItemIndent := countIndent(lines[exceptionItemLine])
				if exceptionItemIndent > indent {
					result.blockContext = schema.BlockException.String()
					break
				}
			}
		}

		if blockCtx := detectBlockStart(trimmed, i, currentLine, indent, indentLevel, isEmptyLine); blockCtx != "" {
			result.blockContext = blockCtx
			break
		}

		if propertyLine == -1 && indent < indentLevel {
			if propName, isMultiLine := extractPropertyName(trimmed, line); propName != "" {
				result.propertyName = propName
				result.inMultiLine = isMultiLine
				propertyLine = i
			}
		}
	}

	return result
}

// blockPrefix maps a YAML line prefix to its block type.
type blockPrefix struct {
	prefix string
	block  string
}

// blockPrefixes defines the recognized top-level block prefixes in Falco rules.
var blockPrefixes = []blockPrefix{
	{"- rule:", schema.BlockRule.String()},
	{"- macro:", schema.BlockMacro.String()},
	{"- list:", schema.BlockList.String()},
	{"- required_engine_version:", schema.PropRequiredEngineVersion.String()},
	{"- required_plugin_versions:", schema.PropRequiredPluginVersions.String()},
}

// detectBlockStart checks if a line starts a block (rule, macro, list, etc.).
func detectBlockStart(trimmed string, lineIndex, currentLine, indent, indentLevel int, isEmptyLine bool) string {
	for _, bp := range blockPrefixes {
		if strings.HasPrefix(trimmed, bp.prefix) {
			if lineIndex == currentLine ||
				indent < indentLevel ||
				(isEmptyLine && indent == 0) ||
				(indentLevel <= 2 && indent == 0) {
				return bp.block
			}
		}
	}

	return ""
}

// =============================================================================
// Property Parsing
// =============================================================================

// parsePropertyName extracts the property name before the colon from a line.
// Returns empty string if no valid property name is found.
func parsePropertyName(line string) string {
	trimmed := strings.TrimSpace(line)
	colonIdx := strings.Index(trimmed, ":")
	if colonIdx <= 0 {
		return ""
	}
	propName := strings.TrimPrefix(trimmed, "- ")
	if colonIdx2 := strings.Index(propName, ":"); colonIdx2 > 0 {
		propName = propName[:colonIdx2]
	}
	return strings.TrimSpace(propName)
}

// isMultiLineIndicator checks if the value after colon indicates a multi-line block.
func isMultiLineIndicator(afterColon string) bool {
	trimmed := strings.TrimSpace(afterColon)
	return trimmed == "|" || trimmed == ">" || trimmed == "|+" || trimmed == ">+" || trimmed == "|-" || trimmed == ">-"
}

// extractPropertyName extracts the property name from a line and detects multi-line blocks.
func extractPropertyName(trimmed, fullLine string) (string, bool) {
	propName := parsePropertyName(trimmed)
	if propName == "" {
		return "", false
	}

	isMultiLine := false
	if _, after, found := strings.Cut(fullLine, ":"); found {
		isMultiLine = isMultiLineIndicator(after)
	}

	return propName, isMultiLine
}

// resolvePropertyContext maps a property name to its context.
func resolvePropertyContext(propertyName string, inExceptionBlock bool) string {
	switch propertyName {
	case schema.PropCondition.String():
		return schema.PropCondition.String()
	case schema.PropOutput.String():
		return schema.PropOutput.String()
	case schema.PropPriority.String():
		return schema.PropPriority.String()
	case schema.PropSource.String():
		return schema.PropSource.String()
	case schema.PropTags.String():
		return schema.PropTags.String()
	case schema.PropEnabled.String(), schema.PropAppend.String(),
		schema.PropSkipIfUnknown.String(), schema.PropCapture.String():
		return propertyName
	case schema.PropItems.String():
		return schema.PropItems.String()
	case schema.PropExceptions.String():
		return schema.PropExceptions.String()
	case schema.PropOverride.String():
		return schema.PropOverride.String()
	case schema.PropExceptionFields.String():
		if inExceptionBlock {
			return schema.ExceptionContextFields.String()
		}
	case schema.PropExceptionComps.String():
		if inExceptionBlock {
			return schema.ExceptionContextComps.String()
		}
	case schema.PropExceptionValues.String():
		if inExceptionBlock {
			return schema.ExceptionContextValues.String()
		}
	case schema.PropExceptionName.String():
		if inExceptionBlock {
			return schema.ExceptionContextName.String()
		}
	}
	return ""
}

// checkCurrentLineProperty checks the current line for property context.
func checkCurrentLineProperty(currentLineText string) string {
	propName := parsePropertyName(currentLineText)
	if propName == "" {
		return ""
	}

	switch propName {
	case schema.PropPriority.String():
		return schema.PropPriority.String()
	case schema.PropSource.String():
		return schema.PropSource.String()
	case schema.PropEnabled.String(), schema.PropAppend.String(), schema.PropSkipIfUnknown.String():
		return propName
	case schema.PropCondition.String():
		return schema.PropCondition.String()
	case schema.PropOutput.String():
		return schema.PropOutput.String()
	case schema.PropTags.String():
		return schema.PropTags.String()
	default:
		return ""
	}
}

// =============================================================================
// Indentation Helpers
// =============================================================================

// countIndent counts the indentation level of a line.
func countIndent(line string) int {
	count := 0
	for _, ch := range line {
		switch ch {
		case ' ':
			count++
		case '\t':
			count += config.DefaultTabSize
		default:
			return count
		}
	}
	return count
}
