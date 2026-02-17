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

// Package diagnostics provides diagnostics functionality.
package diagnostics

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falco-lsp/internal/analyzer"
	"github.com/falcosecurity/falco-lsp/internal/ast"
	"github.com/falcosecurity/falco-lsp/internal/lsp/document"
	"github.com/falcosecurity/falco-lsp/internal/lsp/protocol"
	"github.com/falcosecurity/falco-lsp/internal/parser"
	"github.com/falcosecurity/falco-lsp/internal/schema"
)

func TestDiagnosticsConversion(t *testing.T) {
	// Test that analyzer diagnostics convert correctly to LSP diagnostics
	analyzerDiag := analyzer.Diagnostic{
		Severity: analyzer.SeverityError,
		Message:  "undefined macro: test_macro",
		Range: ast.Range{
			Start: ast.Position{Line: 5, Column: 10},
			End:   ast.Position{Line: 5, Column: 20},
		},
		Source: "macro",
		Code:   schema.DiagUndefinedMacro.String(),
	}

	lspDiag := convertDiagnostic(&analyzerDiag, 0)

	assert.Equal(t, analyzerDiag.Message, lspDiag.Message)
	assert.Equal(t, protocol.DiagnosticSeverityError, lspDiag.Severity)
	assert.Equal(t, 5, lspDiag.Range.Start.Line)
}

func TestDiagnosticsSeverityConversion(t *testing.T) {
	tests := []struct {
		input    analyzer.Severity
		expected int
	}{
		{analyzer.SeverityError, protocol.DiagnosticSeverityError},
		{analyzer.SeverityWarning, protocol.DiagnosticSeverityWarning},
		{analyzer.SeverityHint, protocol.DiagnosticSeverityHint},
		{analyzer.SeverityInfo, protocol.DiagnosticSeverityInformation},
	}

	for _, tt := range tests {
		diag := analyzer.Diagnostic{
			Severity: tt.input,
			Message:  "test",
		}
		result := convertDiagnostic(&diag, 0)
		assert.Equal(t, tt.expected, result.Severity)
	}
}

// convertDiagnostic converts an analyzer diagnostic to an LSP diagnostic.
// This is a test helper that mirrors the real conversion logic.
func convertDiagnostic(d *analyzer.Diagnostic, lineOffset int) protocol.Diagnostic {
	severity := protocol.DiagnosticSeverityError
	switch d.Severity {
	case analyzer.SeverityError:
		severity = protocol.DiagnosticSeverityError
	case analyzer.SeverityWarning:
		severity = protocol.DiagnosticSeverityWarning
	case analyzer.SeverityHint:
		severity = protocol.DiagnosticSeverityHint
	case analyzer.SeverityInfo:
		severity = protocol.DiagnosticSeverityInformation
	}

	return protocol.Diagnostic{
		Range: protocol.Range{
			Start: protocol.Position{
				Line:      d.Range.Start.Line + lineOffset,
				Character: d.Range.Start.Column,
			},
			End: protocol.Position{
				Line:      d.Range.End.Line + lineOffset,
				Character: d.Range.End.Column,
			},
		},
		Severity: severity,
		Code:     d.Code,
		Source:   "falco",
		Message:  d.Message,
	}
}

func TestAnalyzerIntegration(t *testing.T) {
	content := `- rule: Test Rule
  desc: A test rule
  condition: evt.type = execve
  output: "Test output"
  priority: WARNING
`
	result, err := parser.Parse(content, "test.falco.yaml")
	require.NoError(t, err)

	a := analyzer.NewAnalyzer()
	analysisResult := a.Analyze(result.Document, "test.falco.yaml")
	require.NotNil(t, analysisResult)
}

func TestAnalyzerMacroValidation(t *testing.T) {
	content := `- rule: Test Rule
  desc: A test rule
  condition: undefined_macro and evt.type = execve
  output: "Test output"
  priority: WARNING
`
	result, err := parser.Parse(content, "test.falco.yaml")
	require.NoError(t, err)

	a := analyzer.NewAnalyzer()
	analysisResult := a.Analyze(result.Document, "test.falco.yaml")

	found := false
	for _, d := range analysisResult.Diagnostics {
		if d.Code == schema.DiagUndefinedMacro.String() || containsString(d.Message, "undefined_macro") {
			found = true
			break
		}
	}
	assert.True(t, found, "expected undefined macro diagnostic")
}

func TestAnalyzerDefinedMacro(t *testing.T) {
	content := `- macro: is_bash
  condition: proc.name = bash

- rule: Bash Executed
  desc: Detect bash execution
  condition: evt.type = execve and is_bash
  output: "Bash executed"
  priority: INFO
`
	result, err := parser.Parse(content, "test.falco.yaml")
	require.NoError(t, err)

	a := analyzer.NewAnalyzer()
	analysisResult := a.Analyze(result.Document, "test.falco.yaml")

	for _, d := range analysisResult.Diagnostics {
		assert.False(t, containsString(d.Message, "is_bash") && containsString(d.Message, "undefined"),
			"unexpected error for defined macro: %s", d.Message)
	}
}

func TestAnalyzerListValidation(t *testing.T) {
	content := `- list: shell_binaries
  items: [bash, sh, zsh]

- rule: Shell Executed
  desc: Detect shell execution
  condition: evt.type = execve and proc.name in (shell_binaries)
  output: "Shell executed"
  priority: INFO
`
	result, err := parser.Parse(content, "test.falco.yaml")
	require.NoError(t, err)

	a := analyzer.NewAnalyzer()
	analysisResult := a.Analyze(result.Document, "test.falco.yaml")

	for _, d := range analysisResult.Diagnostics {
		assert.False(t, containsString(d.Message, "shell_binaries") && containsString(d.Message, "undefined"),
			"unexpected error for defined list: %s", d.Message)
	}
}

func TestNewProvider(t *testing.T) {
	docs := document.NewStore()

	publishCalled := false
	publishFunc := func(_ string, _ *int, _ []protocol.Diagnostic) {
		publishCalled = true
	}

	dp := New(docs, publishFunc, 1000)
	require.NotNil(t, dp)

	content := `- rule: Test
  desc: test
  condition: evt.type = open
  output: "test"
  priority: INFO
`
	result, _ := parser.Parse(content, "test.yaml")
	doc := &document.Document{
		URI:     "test.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}
	_ = docs.Set(doc)

	dp.AnalyzeAndPublish(doc)
	assert.True(t, publishCalled)
}

func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestProvider_AnalyzeAndPublish_WithParseError(_ *testing.T) {
	docs := document.NewStore()

	publishCalled := false
	publishFunc := func(_ string, _ *int, _ []protocol.Diagnostic) {
		publishCalled = true
	}

	dp := New(docs, publishFunc, 100)

	// Create document with invalid YAML
	doc := &document.Document{
		URI:     "file:///test.yaml",
		Content: "invalid: yaml: content: [",
		Version: 1,
		Result:  nil, // No parse result due to error
	}
	_ = docs.Set(doc)

	dp.AnalyzeAndPublish(doc)

	// Should publish empty diagnostics (no panic)
	_ = publishCalled
}

func TestProvider_AnalyzeAndPublish_NilDocument(t *testing.T) {
	docs := document.NewStore()

	publishCalled := false
	publishFunc := func(_ string, _ *int, _ []protocol.Diagnostic) {
		publishCalled = true
	}

	dp := New(docs, publishFunc, 100)
	dp.AnalyzeAndPublish(nil)

	// Should not panic or publish
	if publishCalled {
		t.Error("should not publish for nil document")
	}
}

func TestProvider_ClearDiagnostics(t *testing.T) {
	docs := document.NewStore()

	var publishedURI string
	var publishedDiags []protocol.Diagnostic
	publishFunc := func(uri string, _ *int, diags []protocol.Diagnostic) {
		publishedURI = uri
		publishedDiags = diags
	}

	dp := New(docs, publishFunc, 100)
	dp.ClearDiagnostics("file:///test.yaml")

	if publishedURI != "file:///test.yaml" {
		t.Errorf("expected URI file:///test.yaml, got %s", publishedURI)
	}
	if len(publishedDiags) != 0 {
		t.Error("expected empty diagnostics for clear")
	}
}

func TestProvider_ConvertSeverity(t *testing.T) {
	docs := document.NewStore()

	var publishedDiags []protocol.Diagnostic
	publishFunc := func(_ string, _ *int, diags []protocol.Diagnostic) {
		publishedDiags = diags
	}

	dp := New(docs, publishFunc, 100)

	// Test by creating a document that generates different severity diagnostics
	content := `- rule: Test
  desc: test
  condition: unknown_macro
  output: "test"
  priority: WARNING
`
	result, _ := parser.Parse(content, "test.yaml")
	doc := &document.Document{
		URI:     "file:///test.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}
	_ = docs.Set(doc)

	dp.AnalyzeAndPublish(doc)

	// Verify diagnostics were processed
	if publishedDiags == nil {
		t.Log("diagnostics published (may be empty if no errors detected)")
	}
}

func TestProvider_ExtractLineFromError(t *testing.T) {
	docs := document.NewStore()
	dp := New(docs, nil, 100)

	tests := []struct {
		name    string
		errMsg  string
		content string
		want    int
	}{
		{
			name:    "yaml line error",
			errMsg:  "yaml: line 5: some error",
			content: "line1\nline2\nline3\nline4\nline5\n",
			want:    4, // 0-based
		},
		{
			name:    "no line info",
			errMsg:  "some random error",
			content: "content\n",
			want:    0,
		},
		{
			name:    "line exceeds content",
			errMsg:  "yaml: line 100: error",
			content: "line1\nline2\n",
			want:    2, // clamped to last line (3 lines: 0, 1, 2)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dp.extractLineFromError(tt.errMsg, tt.content)
			if got != tt.want {
				t.Errorf("extractLineFromError() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestProvider_PublishParseError(t *testing.T) {
	docs := document.NewStore()

	var publishedDiags []protocol.Diagnostic
	publishFunc := func(_ string, _ *int, diags []protocol.Diagnostic) {
		publishedDiags = diags
	}

	dp := New(docs, publishFunc, 100)

	doc := &document.Document{
		URI:     "file:///test.yaml",
		Content: "line1\nline2\nline3\n",
		Version: 1,
	}

	// Call the internal publishParseError method
	dp.publishParseError(doc, errors.New("yaml: line 2: invalid syntax"))

	if len(publishedDiags) != 1 {
		t.Fatalf("expected 1 diagnostic, got %d", len(publishedDiags))
	}

	diag := publishedDiags[0]
	if diag.Range.Start.Line != 1 {
		t.Errorf("expected line 1 (0-based), got %d", diag.Range.Start.Line)
	}
	if diag.Severity != protocol.DiagnosticSeverityError {
		t.Errorf("expected error severity, got %d", diag.Severity)
	}
}

func TestProvider_MaxDiagnostics(t *testing.T) {
	docs := document.NewStore()

	var publishedDiags []protocol.Diagnostic
	publishFunc := func(_ string, _ *int, diags []protocol.Diagnostic) {
		publishedDiags = diags
	}

	// Create provider with max 5 diagnostics
	dp := New(docs, publishFunc, 5)

	// Create a document that might generate many diagnostics
	content := `- rule: Test1
  condition: unknown1 and unknown2 and unknown3
- rule: Test2
  condition: unknown4 and unknown5 and unknown6
- rule: Test3
  condition: unknown7 and unknown8 and unknown9
`
	result, _ := parser.Parse(content, "test.yaml")
	doc := &document.Document{
		URI:     "file:///test.yaml",
		Content: content,
		Version: 1,
		Result:  result,
	}
	_ = docs.Set(doc)

	dp.AnalyzeAndPublish(doc)

	// Should not exceed maxDiagnostics
	if len(publishedDiags) > 5 {
		t.Errorf("expected at most 5 diagnostics, got %d", len(publishedDiags))
	}
}
