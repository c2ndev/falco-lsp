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

package analyzer

import (
	"fmt"
	"strings"

	"github.com/c2ndev/falco-lsp/internal/ast"
	"github.com/c2ndev/falco-lsp/internal/condition"
	"github.com/c2ndev/falco-lsp/internal/parser"
	"github.com/c2ndev/falco-lsp/internal/schema"
)

// validateRequiredFields validates that required fields are present in rules, macros, and lists.
func (a *Analyzer) validateRequiredFields(doc *parser.Document) {
	for _, item := range doc.Items {
		switch it := item.(type) {
		case parser.Rule:
			// Skip validation for append rules (they don't need all fields)
			if it.Append {
				continue
			}

			// Check required fields for rules
			if strings.TrimSpace(it.Desc) == "" {
				a.addDiagnostic(SeverityError,
					"rule 'desc' is required",
					ast.Range{
						Start: ast.Position{Line: it.Line, Column: it.Column},
						End:   ast.Position{Line: it.Line, Column: it.Column + len(it.Name)},
					},
					"rule", "missing-required-field")
			}
			if strings.TrimSpace(it.Condition) == "" {
				a.addDiagnostic(SeverityError,
					"rule 'condition' is required",
					ast.Range{
						Start: ast.Position{Line: it.Line, Column: it.Column},
						End:   ast.Position{Line: it.Line, Column: it.Column + len(it.Name)},
					},
					"rule", "missing-required-field")
			}
			if strings.TrimSpace(it.Output) == "" {
				a.addDiagnostic(SeverityError,
					"rule 'output' is required",
					ast.Range{
						Start: ast.Position{Line: it.Line, Column: it.Column},
						End:   ast.Position{Line: it.Line, Column: it.Column + len(it.Name)},
					},
					"rule", "missing-required-field")
			}
			if strings.TrimSpace(it.Priority) == "" {
				a.addDiagnostic(SeverityError,
					"rule 'priority' is required",
					ast.Range{
						Start: ast.Position{Line: it.Line, Column: it.Column},
						End:   ast.Position{Line: it.Line, Column: it.Column + len(it.Name)},
					},
					"rule", "missing-required-field")
			}

		case parser.Macro:
			// Skip validation for append macros
			if it.Append {
				continue
			}

			// Check required fields for macros
			if strings.TrimSpace(it.Condition) == "" {
				a.addDiagnostic(SeverityError,
					"macro 'condition' is required",
					ast.Range{
						Start: ast.Position{Line: it.Line, Column: it.Column},
						End:   ast.Position{Line: it.Line, Column: it.Column + len(it.Name)},
					},
					"macro", "missing-required-field")
			}

		case parser.List:
			// Skip validation for append lists
			if it.Append {
				continue
			}

			// Check required fields for lists
			// Note: Empty items (items: []) is valid in Falco as a placeholder for append
			if !it.HasItems {
				a.addDiagnostic(SeverityError,
					"list 'items' is required",
					ast.Range{
						Start: ast.Position{Line: it.Line, Column: it.Column},
						End:   ast.Position{Line: it.Line, Column: it.Column + len(it.Name)},
					},
					"list", "missing-required-field")
			}
		}
	}
}

// validateConditions validates all conditions in a document.
func (a *Analyzer) validateConditions(doc *parser.Document) {
	for _, item := range doc.Items {
		switch it := item.(type) {
		case parser.Macro:
			// Don't validate field sources in macros - they are context-dependent
			// and will be validated when used in rules with a specific source.
			// We still validate syntax and references (undefined macros/lists).
			a.validateCondition(it.Condition, "", it.ConditionLine, it.ConditionCol)
		case parser.Rule:
			source := it.Source
			if source == "" {
				source = schema.DefaultSource.String()
			}
			a.currentSource = source
			a.validateCondition(it.Condition, source, it.ConditionLine, it.ConditionCol)
		}
	}
}

// validateCondition validates a single condition expression.
func (a *Analyzer) validateCondition(conditionStr, source string, line, col int) {
	if conditionStr == "" {
		return
	}

	result := condition.Parse(conditionStr)

	// Add parse errors with adjusted line numbers
	for _, err := range result.Errors {
		adjustedRange := a.adjustRangeForLine(err.Range, line, col)
		a.addDiagnostic(SeverityError, err.Message, adjustedRange, "condition", "parse-error")
	}

	// Walk the AST and validate references
	if result.Expression != nil {
		a.walkExpression(result.Expression, source, line, col)
	}
}

// validateField validates a field reference with line adjustment for proper error positioning.
func (a *Analyzer) validateField(field *ast.FieldExpr, source string, line, col int) {
	adjustedRange := a.adjustRangeForLine(field.Range, line, col)

	f := a.fieldRegistry.GetField(field.Name)
	if f == nil {
		a.addDiagnostic(SeverityWarning,
			fmt.Sprintf("unknown field: %s", field.Name),
			adjustedRange, "field", schema.DiagUnknownField.String())
		return
	}

	// Check if field is available for the source
	if !a.isFieldValidForSource(field.Name, source) {
		a.addDiagnostic(SeverityWarning,
			fmt.Sprintf("field %s may not be available for source %s", field.Name, source),
			adjustedRange, "field", schema.DiagWrongSource.String())
	}

	// Check dynamic field argument
	// Skip if field already has an explicit argument in brackets (e.g., proc.aname[1])
	// Also skip if the field name pattern suggests embedded argument (e.g., evt.arg.flags, proc.aname)
	if f.IsDynamic && field.Argument == "" && !a.hasImplicitArgument(field.Name, f.Name) {
		a.addDiagnostic(SeverityHint,
			fmt.Sprintf("field %s is dynamic and may require an argument", field.Name),
			adjustedRange, "field", schema.DiagMissingArgument.String())
	}
}

// hasImplicitArgument checks if a field usage has an implicit argument embedded in its name.
// For example, evt.arg.flags uses evt.arg as base with flags as the implicit argument.
// Similarly, proc.aname refers to ancestor process name without needing explicit [N] index.
func (a *Analyzer) hasImplicitArgument(fieldUsage, registeredName string) bool {
	// If the field usage is longer than the registered name,
	// the extra part is the implicit argument (e.g., evt.arg.flags vs evt.arg)
	if len(fieldUsage) > len(registeredName) && strings.HasPrefix(fieldUsage, registeredName) {
		// Check if there's a separator after the registered name
		rest := fieldUsage[len(registeredName):]
		if rest != "" && (rest[0] == '.' || rest[0] == '[') {
			return true
		}
	}
	return false
}

// isFieldValidForSource checks if a field is valid for a given source type.
// Uses the data-driven SourcePrefixMap from the schema package.
func (a *Analyzer) isFieldValidForSource(fieldName, source string) bool {
	// Empty source means we're in a macro - don't validate source-specific fields
	// since macros can be used in different contexts
	if source == "" {
		return true
	}

	// First check if the field is directly available in the registry for this source
	if a.fieldRegistry.IsFieldAvailableForSource(fieldName, source) {
		return true
	}

	// Fall back to prefix-based validation using the data-driven map
	prefixes := schema.GetFieldPrefixesForString(source)
	if prefixes == nil {
		// Unknown source - allow all fields
		return true
	}

	for _, prefix := range prefixes {
		if strings.HasPrefix(fieldName, prefix) {
			return true
		}
	}

	return false
}

// validateMacroRef validates a macro reference with line adjustment.
func (a *Analyzer) validateMacroRef(ref *ast.MacroRef, line, col int) {
	if ref.Name == "" {
		return
	}
	if _, ok := a.symbols.Macros[ref.Name]; !ok {
		adjustedRange := a.adjustRangeForLine(ref.Range, line, col)
		a.addDiagnostic(SeverityWarning,
			fmt.Sprintf("undefined macro: %s", ref.Name),
			adjustedRange, "macro", schema.DiagUndefinedMacro.String())
	}
}

// validateListRef validates a list reference with line adjustment.
func (a *Analyzer) validateListRef(ref *ast.ListRef, line, col int) {
	if ref.Name == "" {
		return
	}
	if _, ok := a.symbols.Lists[ref.Name]; !ok {
		adjustedRange := a.adjustRangeForLine(ref.Range, line, col)
		a.addDiagnostic(SeverityWarning,
			fmt.Sprintf("undefined list: %s", ref.Name),
			adjustedRange, "list", schema.DiagUndefinedList.String())
	}
}
