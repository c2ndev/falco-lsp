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

	"github.com/c2ndev/falco-lsp/internal/ast"
	"github.com/c2ndev/falco-lsp/internal/parser"
)

// symbolInfo contains common fields for symbol collection validation.
type symbolInfo struct {
	name       string
	typeName   string // "macro", "list", "rule"
	line       int
	column     int
	append     bool
	existsFile string // file where existing symbol is defined, empty if not exists
}

// validateSymbol performs common validation for symbol collection.
// Returns true if collection should continue, false if validation failed.
func (a *Analyzer) validateSymbol(info symbolInfo) bool {
	// Check for empty name
	if info.name == "" {
		a.addDiagnostic(SeverityError, fmt.Sprintf("%s name cannot be empty", info.typeName),
			ast.Range{
				Start: ast.Position{Line: info.line, Column: info.column},
				End:   ast.Position{Line: info.line, Column: info.column + len(info.typeName) + 2}, // +2 for ": "
			}, info.typeName, fmt.Sprintf("empty-%s-name", info.typeName))
		return false
	}

	// Check for duplicates in the same file
	if info.existsFile != "" && !info.append && info.existsFile == a.currentFile {
		a.addDiagnostic(SeverityError, fmt.Sprintf("duplicate %s definition: %s", info.typeName, info.name),
			ast.Range{
				Start: ast.Position{Line: info.line, Column: info.column},
				End:   ast.Position{Line: info.line, Column: info.column + len(info.name)},
			}, info.typeName, fmt.Sprintf("duplicate-%s", info.typeName))
	}

	return true
}

// collectSymbols collects all symbol definitions from a document.
func (a *Analyzer) collectSymbols(doc *parser.Document) {
	for _, item := range doc.Items {
		switch it := item.(type) {
		case parser.Macro:
			a.collectMacro(&it)
		case parser.List:
			a.collectList(&it)
		case parser.Rule:
			a.collectRule(&it)
		}
	}
}

func (a *Analyzer) collectMacro(m *parser.Macro) {
	existsFile := ""
	if existing, ok := a.symbols.Macros[m.Name]; ok {
		existsFile = existing.File
	}

	if !a.validateSymbol(symbolInfo{
		name:       m.Name,
		typeName:   "macro",
		line:       m.Line,
		column:     m.Column,
		append:     m.Append,
		existsFile: existsFile,
	}) {
		return
	}

	a.symbols.Macros[m.Name] = &MacroSymbol{
		Name:      m.Name,
		Condition: m.Condition,
		File:      a.currentFile,
		Line:      m.Line,
		Append:    m.Append,
	}
}

func (a *Analyzer) collectList(l *parser.List) {
	existsFile := ""
	if existing, ok := a.symbols.Lists[l.Name]; ok {
		existsFile = existing.File
	}

	if !a.validateSymbol(symbolInfo{
		name:       l.Name,
		typeName:   "list",
		line:       l.Line,
		column:     l.Column,
		append:     l.Append,
		existsFile: existsFile,
	}) {
		return
	}

	a.symbols.Lists[l.Name] = &ListSymbol{
		Name:   l.Name,
		Items:  l.Items,
		File:   a.currentFile,
		Line:   l.Line,
		Append: l.Append,
	}
}

func (a *Analyzer) collectRule(r *parser.Rule) {
	existsFile := ""
	if existing, ok := a.symbols.Rules[r.Name]; ok {
		existsFile = existing.File
	}

	if !a.validateSymbol(symbolInfo{
		name:       r.Name,
		typeName:   "rule",
		line:       r.Line,
		column:     r.Column,
		append:     r.Append,
		existsFile: existsFile,
	}) {
		return
	}

	a.symbols.Rules[r.Name] = &RuleSymbol{
		Name:      r.Name,
		Condition: r.Condition,
		Source:    r.Source,
		File:      a.currentFile,
		Line:      r.Line,
		Append:    r.Append,
		Enabled:   r.Enabled,
	}
}
