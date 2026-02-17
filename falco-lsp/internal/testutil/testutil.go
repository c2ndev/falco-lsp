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

package testutil

import (
	"strings"
	"testing"

	"github.com/falcosecurity/falco-lsp/internal/analyzer"
	"github.com/falcosecurity/falco-lsp/internal/lsp/document"
	"github.com/falcosecurity/falco-lsp/internal/parser"
)

// TestEnv provides a complete test environment with document store and analyzer.
type TestEnv struct {
	Documents *document.Store
	Analyzer  *analyzer.Analyzer
}

// NewTestEnv creates a new test environment with fresh document store and analyzer.
func NewTestEnv() *TestEnv {
	return &TestEnv{
		Documents: document.NewStore(),
		Analyzer:  analyzer.NewAnalyzer(),
	}
}

// AddDocument parses content and adds a document to the store, returning the document.
// It also analyzes the document and populates its Symbols field.
func (e *TestEnv) AddDocument(t *testing.T, uri, content string) *document.Document {
	t.Helper()

	result, err := parser.Parse(content, uri)
	if err != nil {
		t.Fatalf("failed to parse document: %v", err)
	}

	doc := &document.Document{
		URI:     uri,
		Content: content,
		Version: 1,
		Result:  result,
	}

	// Analyze and populate symbols
	if result != nil && result.Document != nil {
		analysisResult := e.Analyzer.Analyze(result.Document, uri)
		doc.Symbols = analysisResult.Symbols
	}

	e.Documents.SetUnchecked(doc)
	return doc
}

// AddRawDocument adds a document without parsing or analyzing.
// Useful for testing error cases or partial documents.
func (e *TestEnv) AddRawDocument(uri, content string) *document.Document {
	doc := &document.Document{
		URI:     uri,
		Content: content,
		Version: 1,
	}
	e.Documents.SetUnchecked(doc)
	return doc
}

// CreateDocument creates a document with parsed content but doesn't add it to the store.
func CreateDocument(t *testing.T, uri, content string) *document.Document {
	t.Helper()

	result, err := parser.Parse(content, uri)
	if err != nil {
		t.Fatalf("failed to parse document: %v", err)
	}

	return &document.Document{
		URI:     uri,
		Content: content,
		Version: 1,
		Result:  result,
	}
}

// AnalyzeDocument parses and analyzes a document, populating its Symbols field.
func AnalyzeDocument(doc *document.Document) {
	if doc == nil || doc.Result == nil || doc.Result.Document == nil {
		return
	}
	a := analyzer.NewAnalyzer()
	result := a.Analyze(doc.Result.Document, doc.URI)
	doc.Symbols = result.Symbols
}

// Common test fixtures

// SimpleRuleContent returns a simple valid rule for testing.
const SimpleRuleContent = `- rule: Test Rule
  desc: A test rule
  condition: evt.type = open
  output: "test output"
  priority: INFO
`

// MacroRuleContent returns content with a macro and a rule that uses it.
const MacroRuleContent = `- macro: is_shell
  condition: proc.name in (bash, sh)

- rule: Shell Spawn
  desc: Detect shell spawn
  condition: is_shell
  output: "shell spawned"
  priority: WARNING
`

// ListMacroRuleContent returns content with a list, macro, and rule.
const ListMacroRuleContent = `- list: shell_binaries
  items: [bash, sh, zsh]

- macro: is_shell
  condition: proc.name in (shell_binaries)

- rule: Shell Spawn
  desc: Detect shell spawn
  condition: is_shell
  output: "shell spawned"
  priority: WARNING
`

// MultipleRulesContent returns content with multiple rules.
const MultipleRulesContent = `- rule: Rule One
  desc: First rule
  condition: evt.type = open
  output: "rule one"
  priority: INFO

- rule: Rule Two
  desc: Second rule
  condition: evt.type = close
  output: "rule two"
  priority: WARNING
`

// Assertion helpers

// AssertNoError fails the test if err is not nil.
func AssertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// AssertError fails the test if err is nil.
func AssertError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// AssertEqual fails the test if got != want.
func AssertEqual[T comparable](t *testing.T, got, want T, msg string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %v, want %v", msg, got, want)
	}
}

// AssertNotNil fails the test if v is nil.
func AssertNotNil(t *testing.T, v any, msg string) {
	t.Helper()
	if v == nil {
		t.Fatalf("%s: got nil", msg)
	}
}

// AssertNil fails the test if v is not nil.
func AssertNil(t *testing.T, v any, msg string) {
	t.Helper()
	if v != nil {
		t.Errorf("%s: expected nil, got %v", msg, v)
	}
}

// AssertLen fails the test if len(slice) != want.
func AssertLen[T any](t *testing.T, slice []T, want int, msg string) {
	t.Helper()
	if len(slice) != want {
		t.Errorf("%s: got len %d, want %d", msg, len(slice), want)
	}
}

// AssertContains fails the test if s does not contain substr.
func AssertContains(t *testing.T, s, substr, msg string) {
	t.Helper()
	if !strings.Contains(s, substr) {
		t.Errorf("%s: %q does not contain %q", msg, s, substr)
	}
}
