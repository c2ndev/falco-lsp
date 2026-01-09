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
