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
	"github.com/c2ndev/falco-lsp/internal/ast"
	"github.com/c2ndev/falco-lsp/internal/fields"
	"github.com/c2ndev/falco-lsp/internal/parser"
)

// Severity represents the severity of a diagnostic.
type Severity int

// Severity constants define the severity levels for diagnostics.
const (
	// SeverityError indicates a critical error that must be fixed.
	SeverityError Severity = iota
	SeverityWarning
	SeverityHint
	SeverityInfo
)

func (s Severity) String() string {
	switch s {
	case SeverityError:
		return "error"
	case SeverityWarning:
		return "warning"
	case SeverityHint:
		return "hint"
	case SeverityInfo:
		return "info"
	default:
		return "unknown"
	}
}

// Diagnostic represents a semantic error or warning.
type Diagnostic struct {
	Severity Severity
	Message  string
	Range    ast.Range
	Source   string // "field", "macro", "list", "rule"
	Code     string // Error code for quick fixes
	Filename string // File where the diagnostic was found
}

// SymbolTable stores all defined symbols (macros, lists, rules).
type SymbolTable struct {
	Macros map[string]*MacroSymbol
	Lists  map[string]*ListSymbol
	Rules  map[string]*RuleSymbol
}

// MacroSymbol represents a macro definition.
type MacroSymbol struct {
	Name      string
	Condition string
	File      string
	Line      int
	Append    bool
}

// ListSymbol represents a list definition.
type ListSymbol struct {
	Name   string
	Items  []string
	File   string
	Line   int
	Append bool
}

// RuleSymbol represents a rule definition.
type RuleSymbol struct {
	Name      string
	Condition string
	Source    string
	File      string
	Line      int
	Append    bool
	Enabled   *bool
}

// Analyzer performs semantic analysis on Falco rules.
//
// Thread-Safety: Analyzer is NOT thread-safe. Each goroutine should
// create its own Analyzer instance using NewAnalyzer().
// Do not share Analyzer instances across goroutines.
//
// The analyzer is designed to be used in a single-threaded context per document.
// The LSP server creates a new Analyzer for each AnalyzeAndPublish call.
type Analyzer struct {
	symbols       *SymbolTable
	diagnostics   []Diagnostic
	fieldRegistry *fields.Registry
	currentFile   string
	currentSource string // Current source type (syscall, k8s_audit, etc.)
}

// NewAnalyzer creates a new semantic analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		symbols: &SymbolTable{
			Macros: make(map[string]*MacroSymbol),
			Lists:  make(map[string]*ListSymbol),
			Rules:  make(map[string]*RuleSymbol),
		},
		fieldRegistry: fields.MustNewRegistry(),
	}
}

// AnalysisResult contains the result of semantic analysis.
type AnalysisResult struct {
	Diagnostics []Diagnostic
	Symbols     *SymbolTable
}

// Analyze performs semantic analysis on a parsed document.
func (a *Analyzer) Analyze(doc *parser.Document, filename string) *AnalysisResult {
	a.currentFile = filename
	a.diagnostics = nil

	// First pass: collect all symbol definitions
	a.collectSymbols(doc)

	// Second pass: validate all conditions and references
	a.validateConditions(doc)

	return &AnalysisResult{
		Diagnostics: a.diagnostics,
		Symbols:     a.symbols,
	}
}

// AnalyzeMultiple analyzes multiple documents together.
func (a *Analyzer) AnalyzeMultiple(docs map[string]*parser.Document) *AnalysisResult {
	a.diagnostics = nil

	// First pass: collect symbols from all files
	for filename, doc := range docs {
		a.currentFile = filename
		a.collectSymbols(doc)
	}

	// Second pass: validate all conditions and references
	for filename, doc := range docs {
		a.currentFile = filename
		a.validateConditions(doc)
	}

	return &AnalysisResult{
		Diagnostics: a.diagnostics,
		Symbols:     a.symbols,
	}
}

// adjustRangeForLine adjusts a range to account for the line offset in the file.
func (a *Analyzer) adjustRangeForLine(r ast.Range, fileLine int) ast.Range {
	// The range from the condition parser is relative to the condition string (line 1)
	// We need to adjust it to be relative to the file
	// Since the condition is on the same line as "condition:", we use fileLine
	return ast.Range{
		Start: ast.Position{
			Line:   fileLine,
			Column: r.Start.Column,
			Offset: r.Start.Offset,
		},
		End: ast.Position{
			Line:   fileLine + (r.End.Line - r.Start.Line),
			Column: r.End.Column,
			Offset: r.End.Offset,
		},
	}
}

// walkExpression walks an expression and validates all references.
// The line parameter is used to adjust ranges for proper error positioning.
func (a *Analyzer) walkExpression(expr ast.Expression, source string, line int) {
	a.walkExpressionContext(expr, source, false, line)
}

// walkExpressionContext walks with context about whether we're in a value position.
func (a *Analyzer) walkExpressionContext(expr ast.Expression, source string, inValuePosition bool, line int) {
	if expr == nil {
		return
	}

	switch node := expr.(type) {
	case *ast.BinaryExpr:
		// For comparison operators (=, contains, etc.): left is field, right is value
		// For binary logical operators (and, or): both sides are field positions
		isComparison := node.Operator.IsComparison()
		a.walkExpressionContext(node.Left, source, false, line)
		a.walkExpressionContext(node.Right, source, isComparison, line)

	case *ast.UnaryExpr:
		a.walkExpressionContext(node.Operand, source, inValuePosition, line)

	case *ast.ParenExpr:
		a.walkExpressionContext(node.Expr, source, inValuePosition, line)

	case *ast.FieldExpr:
		if !inValuePosition {
			a.validateField(node, source, line)
		}

	case *ast.MacroRef:
		if !inValuePosition {
			a.validateMacroRef(node, line)
		}

	case *ast.ListRef:
		a.validateListRef(node, line)

	case *ast.TupleExpr:
		for _, elem := range node.Elements {
			a.walkExpressionContext(elem, source, true, line)
		}
	}
}

func (a *Analyzer) addDiagnostic(severity Severity, message string, r ast.Range, source, code string) {
	a.diagnostics = append(a.diagnostics, Diagnostic{
		Severity: severity,
		Message:  message,
		Range:    r,
		Source:   source,
		Code:     code,
		Filename: a.currentFile,
	})
}

// GetSymbols returns the collected symbols.
func (a *Analyzer) GetSymbols() *SymbolTable {
	return a.symbols
}

// Reset clears the analyzer state.
func (a *Analyzer) Reset() {
	a.symbols = &SymbolTable{
		Macros: make(map[string]*MacroSymbol),
		Lists:  make(map[string]*ListSymbol),
		Rules:  make(map[string]*RuleSymbol),
	}
	a.diagnostics = nil
}
