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

package testutil

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTestEnv(t *testing.T) {
	env := NewTestEnv()

	require.NotNil(t, env, "NewTestEnv returned nil")
	assert.NotNil(t, env.Documents, "Documents is nil")
	assert.NotNil(t, env.Analyzer, "Analyzer is nil")
}

func TestAddDocument(t *testing.T) {
	env := NewTestEnv()

	doc := env.AddDocument(t, "test.yaml", SimpleRuleContent)

	require.NotNil(t, doc, "AddDocument returned nil")
	assert.Equal(t, "test.yaml", doc.URI, "URI mismatch")
	assert.Equal(t, SimpleRuleContent, doc.Content, "Content mismatch")
	assert.NotNil(t, doc.Result, "Result is nil")
	assert.NotNil(t, doc.Symbols, "Symbols is nil")

	// Verify it's in the store
	stored, ok := env.Documents.Get("test.yaml")
	assert.True(t, ok, "Document not found in store")
	assert.Equal(t, doc.URI, stored.URI, "Stored document mismatch")
}

func TestAddRawDocument(t *testing.T) {
	env := NewTestEnv()

	doc := env.AddRawDocument("test.yaml", "invalid content")

	require.NotNil(t, doc, "AddRawDocument returned nil")
	assert.Nil(t, doc.Result, "Result should be nil for raw document")
	assert.Nil(t, doc.Symbols, "Symbols should be nil for raw document")
}

func TestCreateDocument(t *testing.T) {
	doc := CreateDocument(t, "test.yaml", MacroRuleContent)

	require.NotNil(t, doc, "CreateDocument returned nil")
	assert.NotNil(t, doc.Result, "Result is nil")
}

func TestAnalyzeDocument(t *testing.T) {
	doc := CreateDocument(t, "test.yaml", MacroRuleContent)
	AnalyzeDocument(doc)

	require.NotNil(t, doc.Symbols, "Symbols should be populated after AnalyzeDocument")
	assert.NotNil(t, doc.Symbols.Macros["is_shell"], "Macro 'is_shell' not found")
	assert.NotNil(t, doc.Symbols.Rules["Shell Spawn"], "Rule 'Shell Spawn' not found")
}

func TestAssertNoError(t *testing.T) {
	// Should not fail for nil error
	AssertNoError(t, nil)
}

func TestAssertError(t *testing.T) {
	// Should not fail for non-nil error
	AssertError(t, errors.New("test error"))
}

func TestAssertEqual(t *testing.T) {
	AssertEqual(t, 42, 42, "integers")
	AssertEqual(t, "foo", "foo", "strings")
	AssertEqual(t, true, true, "booleans")
}

func TestAssertNotNil(t *testing.T) {
	AssertNotNil(t, "not nil", "string")
	AssertNotNil(t, 42, "int")
}

func TestAssertLen(t *testing.T) {
	AssertLen(t, []int{1, 2, 3}, 3, "slice")
	AssertLen(t, []string{}, 0, "empty slice")
}

func TestAssertContains(t *testing.T) {
	AssertContains(t, "hello world", "world", "contains")
	AssertContains(t, "hello", "hello", "exact match")
}

func TestFixtures(t *testing.T) {
	// Verify all fixtures are valid YAML and can be parsed
	fixtures := map[string]string{
		"SimpleRuleContent":    SimpleRuleContent,
		"MacroRuleContent":     MacroRuleContent,
		"ListMacroRuleContent": ListMacroRuleContent,
		"MultipleRulesContent": MultipleRulesContent,
	}

	for name, content := range fixtures {
		t.Run(name, func(t *testing.T) {
			doc := CreateDocument(t, "test.yaml", content)
			assert.NotNil(t, doc.Result, "fixture %s failed to parse", name)
		})
	}
}
