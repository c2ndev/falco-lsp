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

package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sampleRulesYAML = `
- required_engine_version: 0.26.0

- list: shell_binaries
  items: [bash, sh, zsh, ksh, csh]

- macro: spawned_process
  condition: evt.type = execve and evt.dir = <

- macro: container
  condition: container.id != host

- rule: Shell Spawned in Container
  desc: Detect shell spawned in a container
  condition: spawned_process and container and proc.name in shell_binaries
  output: "Shell spawned in container (user=%user.name command=%proc.cmdline)"
  priority: WARNING
  tags: [container, shell]
`

func TestParseRulesFile(t *testing.T) {
	result, err := Parse(sampleRulesYAML, "test.yaml")

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Document)

	// Should have: 1 engine version + 1 list + 2 macros + 1 rule = 5 items
	assert.Len(t, result.Document.Items, 5)
}

func TestParseList(t *testing.T) {
	yaml := `
- list: shell_binaries
  items: [bash, sh, zsh]
`
	result, err := Parse(yaml, "test.yaml")

	require.NoError(t, err)
	require.Len(t, result.Document.Items, 1)

	list, ok := result.Document.Items[0].(List)
	require.True(t, ok, "expected List")
	assert.Equal(t, "shell_binaries", list.Name)
	assert.Equal(t, []string{"bash", "sh", "zsh"}, list.Items)
}

func TestParseMacro(t *testing.T) {
	yaml := `
- macro: spawned_process
  condition: evt.type = execve and evt.dir = <
`
	result, err := Parse(yaml, "test.yaml")

	require.NoError(t, err)
	require.Len(t, result.Document.Items, 1)

	macro, ok := result.Document.Items[0].(Macro)
	require.True(t, ok, "expected Macro")
	assert.Equal(t, "spawned_process", macro.Name)
	assert.Equal(t, "evt.type = execve and evt.dir = <", macro.Condition)
}

func TestParseRule(t *testing.T) {
	yaml := `
- rule: Test Rule
  desc: A test rule
  condition: proc.name = bash
  output: "Process %proc.name executed"
  priority: WARNING
  source: syscall
  tags: [test, example]
  enabled: true
`
	result, err := Parse(yaml, "test.yaml")

	require.NoError(t, err)
	require.Len(t, result.Document.Items, 1)

	rule, ok := result.Document.Items[0].(Rule)
	require.True(t, ok, "expected Rule")
	assert.Equal(t, "Test Rule", rule.Name)
	assert.Equal(t, "A test rule", rule.Desc)
	assert.Equal(t, "proc.name = bash", rule.Condition)
	assert.Equal(t, `Process %proc.name executed`, rule.Output)
	assert.Equal(t, "WARNING", rule.Priority)
	assert.Equal(t, "syscall", rule.Source)
	assert.Equal(t, []string{"test", "example"}, rule.Tags)
	require.NotNil(t, rule.Enabled)
	assert.True(t, *rule.Enabled)
}

func TestParseAppend(t *testing.T) {
	yaml := `
- list: shell_binaries
  items: [fish, tcsh]
  append: true

- macro: spawned_process
  condition: or evt.type = clone
  append: true

- rule: Test Rule
  condition: and user.name != root
  append: true
`
	result, err := Parse(yaml, "test.yaml")

	require.NoError(t, err)
	require.Len(t, result.Document.Items, 3)

	list, ok := result.Document.Items[0].(List)
	require.True(t, ok)
	assert.True(t, list.Append)

	macro, ok := result.Document.Items[1].(Macro)
	require.True(t, ok)
	assert.True(t, macro.Append)

	rule, ok := result.Document.Items[2].(Rule)
	require.True(t, ok)
	assert.True(t, rule.Append)
}

func TestParseRequiredEngineVersion(t *testing.T) {
	yaml := `
- required_engine_version: 0.26.0
`
	result, err := Parse(yaml, "test.yaml")

	require.NoError(t, err)
	require.Len(t, result.Document.Items, 1)

	rev, ok := result.Document.Items[0].(RequiredEngineVersion)
	require.True(t, ok, "expected RequiredEngineVersion")
	assert.Equal(t, "0.26.0", rev.Version)
}

func TestParseDisabledRule(t *testing.T) {
	yaml := `
- rule: Disabled Rule
  enabled: false
`
	result, err := Parse(yaml, "test.yaml")

	require.NoError(t, err)
	require.Len(t, result.Document.Items, 1)

	rule, ok := result.Document.Items[0].(Rule)
	require.True(t, ok)
	require.NotNil(t, rule.Enabled)
	assert.False(t, *rule.Enabled)
}

func TestParseEmptyFile(t *testing.T) {
	result, err := Parse("", "empty.yaml")

	require.NoError(t, err)
	require.NotNil(t, result.Document)
	assert.Len(t, result.Document.Items, 0)
}

func TestParseInvalidYAML(t *testing.T) {
	yaml := `
- rule: Test
  condition: [invalid yaml here
`
	_, err := Parse(yaml, "invalid.yaml")

	assert.Error(t, err)
}

// --- isItem interface tests ---

func TestItem_Interface(_ *testing.T) {
	// Test that all types implement Item interface
	var _ Item = Rule{}
	var _ Item = Macro{}
	var _ Item = List{}
	var _ Item = RequiredEngineVersion{}
	var _ Item = RequiredPluginVersions{}

	// Call isItem to verify interface compliance
	Rule{}.isItem()
	Macro{}.isItem()
	List{}.isItem()
	RequiredEngineVersion{}.isItem()
	RequiredPluginVersions{}.isItem()
}

// --- safeColumnConvert tests ---

func TestSafeColumnConvert(t *testing.T) {
	tests := []struct {
		input    int
		expected int
	}{
		{1, 0},  // 1-based to 0-based
		{10, 9}, // normal conversion
		{0, 0},  // zero stays zero
		{-1, 0}, // negative clamped to zero
		{-100, 0},
	}

	for _, tt := range tests {
		result := safeColumnConvert(tt.input)
		assert.Equal(t, tt.expected, result, "safeColumnConvert(%d)", tt.input)
	}
}

// --- Exception parsing tests ---

func TestParseRuleWithExceptions(t *testing.T) {
	yaml := `
- rule: Test Rule with Exceptions
  desc: A rule with exceptions
  condition: proc.name = bash
  output: "test output"
  priority: WARNING
  exceptions:
    - name: allowed_users
      fields: [user.name]
      comps: ["="]
      values:
        - [root]
        - [admin]
    - name: allowed_commands
      fields: [proc.name, proc.args]
      comps: ["=", "startswith"]
`
	result, err := Parse(yaml, "test.yaml")

	require.NoError(t, err)
	require.Len(t, result.Document.Items, 1)

	rule, ok := result.Document.Items[0].(Rule)
	require.True(t, ok)
	require.Len(t, rule.Exceptions, 2)

	// First exception
	ex1 := rule.Exceptions[0]
	assert.Equal(t, "allowed_users", ex1.Name)
	assert.Equal(t, []string{"user.name"}, ex1.Fields)
	assert.Equal(t, []string{"="}, ex1.Comps)
	require.Len(t, ex1.Values, 2)
	assert.Equal(t, []string{"root"}, ex1.Values[0])
	assert.Equal(t, []string{"admin"}, ex1.Values[1])

	// Second exception
	ex2 := rule.Exceptions[1]
	assert.Equal(t, "allowed_commands", ex2.Name)
	assert.Equal(t, []string{"proc.name", "proc.args"}, ex2.Fields)
	assert.Equal(t, []string{"=", "startswith"}, ex2.Comps)
}

func TestParseRuleWithEmptyExceptions(t *testing.T) {
	yaml := `
- rule: Test Rule
  exceptions:
`
	result, err := Parse(yaml, "test.yaml")

	require.NoError(t, err)
	require.Len(t, result.Document.Items, 1)

	rule, ok := result.Document.Items[0].(Rule)
	require.True(t, ok)
	// When exceptions is null/empty, parseExceptions returns nil
	assert.Nil(t, rule.Exceptions)
}

// --- Required plugin versions tests ---

func TestParseRequiredPluginVersions(t *testing.T) {
	yaml := `
- required_plugin_versions:
    - name: cloudtrail
      version: 0.6.0
    - name: json
      version: 0.4.0
`
	result, err := Parse(yaml, "test.yaml")

	require.NoError(t, err)
	require.Len(t, result.Document.Items, 1)

	rpv, ok := result.Document.Items[0].(RequiredPluginVersions)
	require.True(t, ok)
	require.Len(t, rpv.Plugins, 2)

	assert.Equal(t, "cloudtrail", rpv.Plugins[0].Name)
	assert.Equal(t, "0.6.0", rpv.Plugins[0].Version)
	assert.Equal(t, "json", rpv.Plugins[1].Name)
	assert.Equal(t, "0.4.0", rpv.Plugins[1].Version)
}

func TestParseRequiredPluginVersionsEmpty(t *testing.T) {
	yaml := `
- required_plugin_versions:
`
	result, err := Parse(yaml, "test.yaml")

	require.NoError(t, err)
	require.Len(t, result.Document.Items, 1)

	rpv, ok := result.Document.Items[0].(RequiredPluginVersions)
	require.True(t, ok)
	assert.Empty(t, rpv.Plugins)
}

// --- Multi-line condition tests ---

func TestParseMultilineConditionFolded(t *testing.T) {
	yaml := `
- rule: Test Rule
  condition: >
    proc.name = bash
    and user.name = root
  output: "test"
  priority: WARNING
`
	result, err := Parse(yaml, "test.yaml")

	require.NoError(t, err)
	require.Len(t, result.Document.Items, 1)

	rule, ok := result.Document.Items[0].(Rule)
	require.True(t, ok)
	assert.True(t, rule.IsFolded, "should detect folded style")
	assert.Contains(t, rule.Condition, "proc.name = bash")
}

func TestParseMultilineConditionLiteral(t *testing.T) {
	yaml := `
- macro: test_macro
  condition: |
    proc.name = bash
    and user.name = root
`
	result, err := Parse(yaml, "test.yaml")

	require.NoError(t, err)
	require.Len(t, result.Document.Items, 1)

	macro, ok := result.Document.Items[0].(Macro)
	require.True(t, ok)
	// Literal style is not considered folded
	assert.False(t, macro.IsFolded, "literal style should not be folded")
	assert.Contains(t, macro.Condition, "proc.name = bash")
}

// --- Line/Column position tests ---

func TestParseLineColumnPositions(t *testing.T) {
	yaml := `- rule: Test Rule
  desc: Description
  condition: proc.name = bash
`
	result, err := Parse(yaml, "test.yaml")

	require.NoError(t, err)
	require.Len(t, result.Document.Items, 1)

	rule, ok := result.Document.Items[0].(Rule)
	require.True(t, ok)
	assert.Equal(t, 1, rule.Line, "rule should start at line 1")
	// Column is 0-based from 1-based YAML: "- rule:" starts at column 1 in YAML -> 0-based
	// But the mapping node (what we parse) includes the "- " so actual column is 2 (3 in 1-based)
	assert.GreaterOrEqual(t, rule.Column, 0, "rule column should be non-negative")
	assert.Greater(t, rule.ConditionLine, 0, "condition line should be set")
	assert.GreaterOrEqual(t, rule.ConditionCol, 0, "condition column should be non-negative")
}

// --- Edge cases ---

func TestParseListWithNoItems(t *testing.T) {
	yaml := `
- list: empty_list
`
	result, err := Parse(yaml, "test.yaml")

	require.NoError(t, err)
	require.Len(t, result.Document.Items, 1)

	list, ok := result.Document.Items[0].(List)
	require.True(t, ok)
	assert.Equal(t, "empty_list", list.Name)
	assert.False(t, list.HasItems, "HasItems should be false when items not specified")
	assert.Nil(t, list.Items)
}

func TestParseListWithEmptyItems(t *testing.T) {
	yaml := `
- list: empty_list
  items: []
`
	result, err := Parse(yaml, "test.yaml")

	require.NoError(t, err)
	require.Len(t, result.Document.Items, 1)

	list, ok := result.Document.Items[0].(List)
	require.True(t, ok)
	assert.True(t, list.HasItems, "HasItems should be true when items explicitly set")
	assert.Empty(t, list.Items)
}

func TestParseUnknownItem(t *testing.T) {
	yaml := `
- unknown_key: some_value
`
	result, err := Parse(yaml, "test.yaml")

	require.NoError(t, err)
	// Unknown items are skipped (return nil from parseItemFromNode)
	assert.Empty(t, result.Document.Items)
}

func TestParseNotSequenceRoot(t *testing.T) {
	yaml := `rule: not_a_sequence`

	_, err := Parse(yaml, "test.yaml")

	// Should error because root is not a sequence
	assert.Error(t, err)
}

func TestParseWhitespaceOnly(t *testing.T) {
	yaml := "   \n\n\t  \n"

	result, err := Parse(yaml, "test.yaml")

	require.NoError(t, err)
	require.NotNil(t, result.Document)
	assert.Empty(t, result.Document.Items)
}

func TestParseMacroNoCondition(t *testing.T) {
	yaml := `
- macro: test_macro
`
	result, err := Parse(yaml, "test.yaml")

	require.NoError(t, err)
	require.Len(t, result.Document.Items, 1)

	macro, ok := result.Document.Items[0].(Macro)
	require.True(t, ok)
	assert.Equal(t, "test_macro", macro.Name)
	assert.Empty(t, macro.Condition)
}

func TestParseNonMappingSequenceItem(t *testing.T) {
	yaml := `
- simple_string_item
- rule: Valid Rule
`
	result, err := Parse(yaml, "test.yaml")

	require.NoError(t, err)
	// Only the valid rule should be parsed
	require.Len(t, result.Document.Items, 1)

	rule, ok := result.Document.Items[0].(Rule)
	require.True(t, ok)
	assert.Equal(t, "Valid Rule", rule.Name)
}

func TestParseRuleWithoutEnabled(t *testing.T) {
	yaml := `
- rule: Test Rule
  desc: Test
`
	result, err := Parse(yaml, "test.yaml")

	require.NoError(t, err)
	require.Len(t, result.Document.Items, 1)

	rule, ok := result.Document.Items[0].(Rule)
	require.True(t, ok)
	assert.Nil(t, rule.Enabled, "enabled should be nil when not specified")
}

func TestParseExceptionsWithNonMappingItem(t *testing.T) {
	yaml := `
- rule: Test Rule
  exceptions:
    - not_a_mapping
`
	result, err := Parse(yaml, "test.yaml")

	require.NoError(t, err)
	require.Len(t, result.Document.Items, 1)

	rule, ok := result.Document.Items[0].(Rule)
	require.True(t, ok)
	// Non-mapping items in exceptions are skipped
	assert.Empty(t, rule.Exceptions)
}

func TestParseExceptionsValuesWithNonSequence(t *testing.T) {
	yaml := `
- rule: Test Rule
  exceptions:
    - name: ex1
      values:
        - not_a_sequence
`
	result, err := Parse(yaml, "test.yaml")

	require.NoError(t, err)
	require.Len(t, result.Document.Items, 1)

	rule, ok := result.Document.Items[0].(Rule)
	require.True(t, ok)
	require.Len(t, rule.Exceptions, 1)
	// Values that are not sequences are skipped
	assert.Empty(t, rule.Exceptions[0].Values)
}

func TestParseRequiredPluginVersionsNonSequence(t *testing.T) {
	yaml := `
- required_plugin_versions: not_a_sequence
`
	result, err := Parse(yaml, "test.yaml")

	require.NoError(t, err)
	require.Len(t, result.Document.Items, 1)

	rpv, ok := result.Document.Items[0].(RequiredPluginVersions)
	require.True(t, ok)
	assert.Empty(t, rpv.Plugins)
}

func TestParseRequiredPluginVersionsNonMappingItem(t *testing.T) {
	yaml := `
- required_plugin_versions:
    - not_a_mapping
`
	result, err := Parse(yaml, "test.yaml")

	require.NoError(t, err)
	require.Len(t, result.Document.Items, 1)

	rpv, ok := result.Document.Items[0].(RequiredPluginVersions)
	require.True(t, ok)
	// Non-mapping items are skipped
	assert.Empty(t, rpv.Plugins)
}
