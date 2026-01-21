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

package diagnostics

import (
	"strconv"
	"strings"

	"github.com/c2ndev/falco-lsp/internal/analyzer"
	"github.com/c2ndev/falco-lsp/internal/config"
	"github.com/c2ndev/falco-lsp/internal/lsp/document"
	"github.com/c2ndev/falco-lsp/internal/lsp/protocol"
	"github.com/c2ndev/falco-lsp/internal/parser"
	"github.com/c2ndev/falco-lsp/internal/version"
)

// PublishFunc is a function type for publishing diagnostics.
type PublishFunc func(uri string, version *int, diagnostics []protocol.Diagnostic)

// Provider handles document diagnostics.
type Provider struct {
	documents      *document.Store
	publish        PublishFunc
	maxDiagnostics int
}

// New creates a new diagnostics provider.
func New(docs *document.Store, publishFn PublishFunc, maxDiagnostics int) *Provider {
	if maxDiagnostics <= 0 {
		maxDiagnostics = config.DefaultMaxDiagnostics
	}
	return &Provider{
		documents:      docs,
		publish:        publishFn,
		maxDiagnostics: maxDiagnostics,
	}
}

// AnalyzeAndPublish analyzes a document and publishes diagnostics.
// This is the main entry point for document validation.
// It creates a new Document with the analysis results and updates the store.
func (p *Provider) AnalyzeAndPublish(doc *document.Document) {
	if doc == nil {
		return
	}

	// Empty document - clear all diagnostics and update store
	if doc.Content == "" {
		newDoc := doc.WithSymbols(nil)
		_ = p.documents.Set(newDoc)
		p.publishDiagnostics(doc.URI, doc.Version, nil)
		return
	}

	// Parse the document
	result, err := parser.Parse(doc.Content, doc.URI)
	if err != nil {
		newDoc := doc.WithSymbols(nil)
		_ = p.documents.Set(newDoc)
		p.publishParseError(doc, err)
		return
	}

	// Create new document with parse result (immutable pattern)
	newDoc := doc.WithResult(result)

	// Create a fresh analyzer for this document
	docAnalyzer := analyzer.NewAnalyzer()

	// Run semantic analysis
	analysisResult := docAnalyzer.Analyze(result.Document, doc.URI)

	// Update document with symbols (immutable pattern)
	newDoc = newDoc.WithSymbols(analysisResult.Symbols)

	// Update the store with the new document
	_ = p.documents.Set(newDoc)

	// Convert to LSP diagnostics
	diagnostics := p.convertDiagnostics(analysisResult.Diagnostics)

	// Publish diagnostics - always publish, even if empty (clears previous errors)
	p.publishDiagnostics(newDoc.URI, newDoc.Version, diagnostics)
}

// Diagnostic codes.
const (
	// CodeParseError is the diagnostic code for YAML parse errors.
	CodeParseError = "parse-error"
)

// publishParseError publishes a parse error as a diagnostic.
func (p *Provider) publishParseError(doc *document.Document, err error) {
	line := p.extractLineFromError(err.Error(), doc.Content)

	diagnostics := []protocol.Diagnostic{{
		Range: protocol.Range{
			Start: protocol.Position{Line: line, Character: 0},
			End:   protocol.Position{Line: line, Character: 1},
		},
		Severity: protocol.DiagnosticSeverityError,
		Message:  err.Error(),
		Source:   version.DiagnosticSource,
		Code:     CodeParseError,
	}}

	p.publishDiagnostics(doc.URI, doc.Version, diagnostics)
}

// extractLineFromError tries to extract a line number from YAML error messages.
func (p *Provider) extractLineFromError(errMsg, content string) int {
	line := 0

	// YAML errors often have format "yaml: line X: ..."
	if strings.Contains(errMsg, "yaml: line ") {
		parts := strings.Split(errMsg, "yaml: line ")
		if len(parts) > 1 {
			lineParts := strings.Split(parts[1], ":")
			if len(lineParts) > 0 {
				if lineNum, parseErr := strconv.Atoi(lineParts[0]); parseErr == nil {
					line = lineNum - 1 // Convert to 0-based

					// Validate line number is within bounds
					lines := strings.Split(content, "\n")
					if line >= len(lines) {
						line = max(0, len(lines)-1)
					}
				}
			}
		}
	}

	return max(0, line)
}

// convertDiagnostics converts analyzer diagnostics to LSP diagnostics.
func (p *Provider) convertDiagnostics(diags []analyzer.Diagnostic) []protocol.Diagnostic {
	if len(diags) == 0 {
		return nil
	}

	result := make([]protocol.Diagnostic, 0, len(diags))

	for _, d := range diags {
		severity := p.convertSeverity(d.Severity)

		// Convert 1-based positions to 0-based for LSP using centralized utilities
		startPos := protocol.ToLSPPosition(d.Range.Start.Line, d.Range.Start.Column)
		endPos := protocol.ToLSPPosition(d.Range.End.Line, d.Range.End.Column)

		result = append(result, protocol.Diagnostic{
			Range:    protocol.NewRange(startPos, endPos),
			Severity: severity,
			Code:     d.Code,
			Message:  d.Message,
			Source:   version.DiagnosticSource,
		})
	}

	return result
}

// convertSeverity converts analyzer severity to LSP severity.
func (p *Provider) convertSeverity(s analyzer.Severity) int {
	switch s {
	case analyzer.SeverityError:
		return protocol.DiagnosticSeverityError
	case analyzer.SeverityWarning:
		return protocol.DiagnosticSeverityWarning
	case analyzer.SeverityInfo:
		return protocol.DiagnosticSeverityInformation
	case analyzer.SeverityHint:
		return protocol.DiagnosticSeverityHint
	default:
		return protocol.DiagnosticSeverityError
	}
}

// publishDiagnostics sends diagnostics to the client.
func (p *Provider) publishDiagnostics(uri string, docVersion int, diagnostics []protocol.Diagnostic) {
	if diagnostics == nil {
		diagnostics = []protocol.Diagnostic{}
	}

	// Limit diagnostics to maxDiagnostics
	if len(diagnostics) > p.maxDiagnostics {
		diagnostics = diagnostics[:p.maxDiagnostics]
	}

	p.publish(uri, &docVersion, diagnostics)
}

// ClearDiagnostics clears all diagnostics for a document.
func (p *Provider) ClearDiagnostics(uri string) {
	p.publish(uri, nil, []protocol.Diagnostic{})
}
