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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/c2ndev/falco-lsp/internal/parser"
	"github.com/c2ndev/falco-lsp/internal/schema"
)

func TestAnalyzeValidRule(t *testing.T) {
	yaml := `
- list: shell_binaries
  items: [bash, sh, zsh]

- macro: spawned_process
  condition: evt.type = execve

- rule: Shell Spawned
  desc: Detect shell spawn
  condition: spawned_process and proc.name in shell_binaries
  output: "Shell spawned"
  priority: WARNING
`
	result, err := parser.Parse(yaml, "test.yaml")
	require.NoError(t, err)

	a := NewAnalyzer()
	analysisResult := a.Analyze(result.Document, "test.yaml")

	// Should have no errors for this valid configuration
	errors := 0
	for _, d := range analysisResult.Diagnostics {
		if d.Severity == SeverityError {
			errors++
		}
	}
	assert.Equal(t, 0, errors, "expected no errors")
}

func TestAnalyzeUndefinedMacro(t *testing.T) {
	yaml := `
- rule: Test Rule
  desc: Test
  condition: undefined_macro and proc.name = bash
  output: "Test"
  priority: WARNING
`
	result, err := parser.Parse(yaml, "test.yaml")
	require.NoError(t, err)

	a := NewAnalyzer()
	analysisResult := a.Analyze(result.Document, "test.yaml")

	// Should have a warning for undefined macro
	hasUndefinedMacroWarning := false
	for _, d := range analysisResult.Diagnostics {
		if d.Code == schema.DiagUndefinedMacro.String() {
			hasUndefinedMacroWarning = true
			break
		}
	}
	assert.True(t, hasUndefinedMacroWarning, "expected undefined macro warning")
}

func TestAnalyzeUndefinedList(t *testing.T) {
	yaml := `
- rule: Test Rule
  desc: Test
  condition: proc.name in undefined_list
  output: "Test"
  priority: WARNING
`
	result, err := parser.Parse(yaml, "test.yaml")
	require.NoError(t, err)

	a := NewAnalyzer()
	analysisResult := a.Analyze(result.Document, "test.yaml")

	// Should have a warning for undefined list
	hasUndefinedListWarning := false
	for _, d := range analysisResult.Diagnostics {
		if d.Code == schema.DiagUndefinedList.String() {
			hasUndefinedListWarning = true
			break
		}
	}
	assert.True(t, hasUndefinedListWarning, "expected undefined list warning")
}

func TestAnalyzeUnknownField(t *testing.T) {
	yaml := `
- rule: Test Rule
  desc: Test
  condition: unknown.field = value
  output: "Test"
  priority: WARNING
`
	result, err := parser.Parse(yaml, "test.yaml")
	require.NoError(t, err)

	a := NewAnalyzer()
	analysisResult := a.Analyze(result.Document, "test.yaml")

	// Should have a warning for unknown field
	hasUnknownFieldWarning := false
	for _, d := range analysisResult.Diagnostics {
		if d.Code == "unknown-field" {
			hasUnknownFieldWarning = true
			break
		}
	}
	assert.True(t, hasUnknownFieldWarning, "expected unknown field warning")
}

func TestAnalyzeMultipleFiles(t *testing.T) {
	// File 1: defines macros and lists
	yaml1 := `
- list: shell_binaries
  items: [bash, sh]

- macro: spawned_process
  condition: evt.type = execve
`
	// File 2: uses macros and lists from file 1
	yaml2 := `
- rule: Shell Spawned
  desc: Detect shell spawn
  condition: spawned_process and proc.name in shell_binaries
  output: "Shell spawned"
  priority: WARNING
`
	result1, err := parser.Parse(yaml1, "macros.yaml")
	require.NoError(t, err)

	result2, err := parser.Parse(yaml2, "rules.yaml")
	require.NoError(t, err)

	a := NewAnalyzer()
	docs := map[string]*parser.Document{
		"macros.yaml": result1.Document,
		"rules.yaml":  result2.Document,
	}

	analysisResult := a.AnalyzeMultiple(docs)

	// Should have no undefined references since macros are defined in another file
	undefinedErrors := 0
	for _, d := range analysisResult.Diagnostics {
		if d.Code == schema.DiagUndefinedMacro.String() || d.Code == schema.DiagUndefinedList.String() {
			undefinedErrors++
		}
	}
	assert.Equal(t, 0, undefinedErrors, "should resolve references across files")
}

func TestAnalyzeDuplicateDefinitions(t *testing.T) {
	yaml := `
- macro: test_macro
  condition: evt.type = execve

- macro: test_macro
  condition: evt.type = clone
`
	result, err := parser.Parse(yaml, "test.yaml")
	require.NoError(t, err)

	a := NewAnalyzer()
	analysisResult := a.Analyze(result.Document, "test.yaml")

	// Should have an error for duplicate macro
	hasDuplicateError := false
	for _, d := range analysisResult.Diagnostics {
		if d.Code == schema.DiagDuplicateMacro.String() {
			hasDuplicateError = true
			break
		}
	}
	assert.True(t, hasDuplicateError, "expected duplicate macro error")
}

func TestAnalyzeAppendDoesNotDuplicate(t *testing.T) {
	yaml := `
- macro: test_macro
  condition: evt.type = execve

- macro: test_macro
  condition: or evt.type = clone
  append: true
`
	result, err := parser.Parse(yaml, "test.yaml")
	require.NoError(t, err)

	a := NewAnalyzer()
	analysisResult := a.Analyze(result.Document, "test.yaml")

	// Should NOT have an error for append
	hasDuplicateError := false
	for _, d := range analysisResult.Diagnostics {
		if d.Code == schema.DiagDuplicateMacro.String() {
			hasDuplicateError = true
			break
		}
	}
	assert.False(t, hasDuplicateError, "append should not be treated as duplicate")
}

func TestSymbolCollection(t *testing.T) {
	yaml := `
- list: shell_binaries
  items: [bash, sh]

- list: network_tools
  items: [nc, ncat]

- macro: spawned_process
  condition: evt.type = execve

- macro: container
  condition: container.id != host

- rule: Test Rule
  desc: Test
  condition: spawned_process
  output: "Test"
  priority: WARNING
`
	result, err := parser.Parse(yaml, "test.yaml")
	require.NoError(t, err)

	a := NewAnalyzer()
	a.Analyze(result.Document, "test.yaml")

	symbols := a.GetSymbols()

	assert.Len(t, symbols.Lists, 2)
	assert.Len(t, symbols.Macros, 2)
	assert.Len(t, symbols.Rules, 1)

	assert.Contains(t, symbols.Lists, "shell_binaries")
	assert.Contains(t, symbols.Lists, "network_tools")
	assert.Contains(t, symbols.Macros, "spawned_process")
	assert.Contains(t, symbols.Macros, "container")
	assert.Contains(t, symbols.Rules, "Test Rule")
}

func TestMacroFieldValidationIsContextIndependent(t *testing.T) {
	// Macros should not generate field source warnings since they can be used
	// in different contexts (syscall, k8s_audit, etc.)
	yaml := `
- macro: k8s_macro
  condition: ka.user.name = "admin"

- macro: syscall_macro
  condition: proc.name = "bash"

- rule: K8s Rule
  desc: Uses k8s_audit fields
  condition: k8s_macro and ka.verb = "create"
  output: "K8s event"
  priority: WARNING
  source: k8s_audit

- rule: Syscall Rule
  desc: Uses syscall fields
  condition: syscall_macro and evt.type = execve
  output: "Syscall event"
  priority: WARNING
  source: syscall
`
	result, err := parser.Parse(yaml, "test.yaml")
	require.NoError(t, err)

	a := NewAnalyzer()
	analysisResult := a.Analyze(result.Document, "test.yaml")

	// Check that macros don't generate "wrong-source" warnings
	wrongSourceWarnings := 0
	for _, d := range analysisResult.Diagnostics {
		if d.Code == schema.DiagWrongSource.String() {
			t.Logf("Unexpected wrong-source warning: %s at line %d", d.Message, d.Range.Start.Line)
			wrongSourceWarnings++
		}
	}

	assert.Equal(t, 0, wrongSourceWarnings, "macros should not generate field source warnings")
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityError, "error"},
		{SeverityWarning, "warning"},
		{SeverityHint, "hint"},
		{SeverityInfo, "info"},
		{Severity(99), "unknown"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, tt.severity.String())
	}
}

func TestAnalyzerReset(t *testing.T) {
	yaml := `
- macro: test_macro
  condition: evt.type = execve
`
	result, err := parser.Parse(yaml, "test.yaml")
	require.NoError(t, err)

	a := NewAnalyzer()
	a.Analyze(result.Document, "test.yaml")

	// Should have symbols
	symbols := a.GetSymbols()
	assert.Len(t, symbols.Macros, 1)

	// Reset
	a.Reset()

	// Should be empty
	symbols = a.GetSymbols()
	assert.Len(t, symbols.Macros, 0)
	assert.Len(t, symbols.Lists, 0)
	assert.Len(t, symbols.Rules, 0)
}

func TestAnalyzeWrongSourceField(t *testing.T) {
	// Using k8s_audit field in syscall rule
	yaml := `
- rule: Wrong Source
  desc: Test
  condition: ka.user.name = "admin"
  output: "Test"
  priority: WARNING
  source: syscall
`
	result, err := parser.Parse(yaml, "test.yaml")
	require.NoError(t, err)

	a := NewAnalyzer()
	analysisResult := a.Analyze(result.Document, "test.yaml")

	// Should have a warning for wrong source
	hasWrongSourceWarning := false
	for _, d := range analysisResult.Diagnostics {
		if d.Code == schema.DiagWrongSource.String() {
			hasWrongSourceWarning = true
			break
		}
	}
	assert.True(t, hasWrongSourceWarning, "expected wrong source warning")
}

func TestAnalyzeK8sAuditSource(t *testing.T) {
	yaml := `
- rule: K8s Rule
  desc: Test
  condition: ka.user.name = "admin"
  output: "Test"
  priority: WARNING
  source: k8s_audit
`
	result, err := parser.Parse(yaml, "test.yaml")
	require.NoError(t, err)

	a := NewAnalyzer()
	analysisResult := a.Analyze(result.Document, "test.yaml")

	// Should NOT have wrong source warning
	hasWrongSourceWarning := false
	for _, d := range analysisResult.Diagnostics {
		if d.Code == schema.DiagWrongSource.String() {
			hasWrongSourceWarning = true
			break
		}
	}
	assert.False(t, hasWrongSourceWarning, "k8s_audit field in k8s_audit rule should be valid")
}

func TestAnalyzeListWithEmptyName(t *testing.T) {
	yaml := `
- list: ""
  items: [bash, sh]
`
	result, err := parser.Parse(yaml, "test.yaml")
	require.NoError(t, err)

	a := NewAnalyzer()
	analysisResult := a.Analyze(result.Document, "test.yaml")

	// Should have an error for empty name
	hasEmptyNameError := false
	for _, d := range analysisResult.Diagnostics {
		if d.Code == "empty-list-name" {
			hasEmptyNameError = true
			break
		}
	}
	assert.True(t, hasEmptyNameError, "expected empty list name error")
}

func TestAnalyzeMacroWithEmptyName(t *testing.T) {
	yaml := `
- macro: ""
  condition: evt.type = execve
`
	result, err := parser.Parse(yaml, "test.yaml")
	require.NoError(t, err)

	a := NewAnalyzer()
	analysisResult := a.Analyze(result.Document, "test.yaml")

	// Should have an error for empty name
	hasEmptyNameError := false
	for _, d := range analysisResult.Diagnostics {
		if d.Code == "empty-macro-name" {
			hasEmptyNameError = true
			break
		}
	}
	assert.True(t, hasEmptyNameError, "expected empty macro name error")
}

func TestAnalyzeRuleWithEmptyName(t *testing.T) {
	yaml := `
- rule: ""
  desc: Test
  condition: evt.type = execve
  output: "Test"
  priority: WARNING
`
	result, err := parser.Parse(yaml, "test.yaml")
	require.NoError(t, err)

	a := NewAnalyzer()
	analysisResult := a.Analyze(result.Document, "test.yaml")

	// Should have an error for empty name
	hasEmptyNameError := false
	for _, d := range analysisResult.Diagnostics {
		if d.Code == "empty-rule-name" {
			hasEmptyNameError = true
			break
		}
	}
	assert.True(t, hasEmptyNameError, "expected empty rule name error")
}

func TestAnalyzeDuplicateList(t *testing.T) {
	yaml := `
- list: test_list
  items: [a, b]

- list: test_list
  items: [c, d]
`
	result, err := parser.Parse(yaml, "test.yaml")
	require.NoError(t, err)

	a := NewAnalyzer()
	analysisResult := a.Analyze(result.Document, "test.yaml")

	// Should have an error for duplicate list
	hasDuplicateError := false
	for _, d := range analysisResult.Diagnostics {
		if d.Code == "duplicate-list" {
			hasDuplicateError = true
			break
		}
	}
	assert.True(t, hasDuplicateError, "expected duplicate list error")
}

func TestAnalyzeDuplicateRule(t *testing.T) {
	yaml := `
- rule: Test Rule
  desc: Test
  condition: evt.type = execve
  output: "Test"
  priority: WARNING

- rule: Test Rule
  desc: Test 2
  condition: evt.type = clone
  output: "Test 2"
  priority: WARNING
`
	result, err := parser.Parse(yaml, "test.yaml")
	require.NoError(t, err)

	a := NewAnalyzer()
	analysisResult := a.Analyze(result.Document, "test.yaml")

	// Should have an error for duplicate rule
	hasDuplicateError := false
	for _, d := range analysisResult.Diagnostics {
		if d.Code == "duplicate-rule" {
			hasDuplicateError = true
			break
		}
	}
	assert.True(t, hasDuplicateError, "expected duplicate rule error")
}

func TestHasImplicitArgument(t *testing.T) {
	a := NewAnalyzer()

	tests := []struct {
		name           string
		fieldUsage     string
		registeredName string
		expected       bool
	}{
		{
			name:           "evt.arg.flags has implicit argument",
			fieldUsage:     "evt.arg.flags",
			registeredName: "evt.arg",
			expected:       true,
		},
		{
			name:           "evt.arg with bracket index",
			fieldUsage:     "evt.arg[0]",
			registeredName: "evt.arg",
			expected:       true,
		},
		{
			name:           "exact match - no implicit argument",
			fieldUsage:     "proc.name",
			registeredName: "proc.name",
			expected:       false,
		},
		{
			name:           "shorter usage than registered",
			fieldUsage:     "proc",
			registeredName: "proc.name",
			expected:       false,
		},
		{
			name:           "different prefix",
			fieldUsage:     "fd.name",
			registeredName: "proc.name",
			expected:       false,
		},
		{
			name:           "no separator after registered name",
			fieldUsage:     "evt.argx",
			registeredName: "evt.arg",
			expected:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := a.hasImplicitArgument(tt.fieldUsage, tt.registeredName)
			assert.Equal(t, tt.expected, result)
		})
	}
}
