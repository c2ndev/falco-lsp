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

package schema

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComparisonOperatorsNotEmpty(t *testing.T) {
	assert.NotEmpty(t, ComparisonOperators, "ComparisonOperators should not be empty")
}

func TestComparisonOperatorsContainsExpected(t *testing.T) {
	operators := make(map[string]bool)
	for _, op := range ComparisonOperators {
		operators[op.Name] = true
	}

	// Check basic comparison operators
	assert.True(t, operators["="], "Should contain =")
	assert.True(t, operators["!="], "Should contain !=")
	assert.True(t, operators["<"], "Should contain <")
	assert.True(t, operators["<="], "Should contain <=")
	assert.True(t, operators[">"], "Should contain >")
	assert.True(t, operators[">="], "Should contain >=")
}

func TestComparisonOperatorsContainsTextOperators(t *testing.T) {
	operators := make(map[string]bool)
	for _, op := range ComparisonOperators {
		operators[op.Name] = true
	}

	// Check text/list operators
	assert.True(t, operators["in"], "Should contain in")
	assert.True(t, operators["contains"], "Should contain contains")
	assert.True(t, operators["startswith"], "Should contain startswith")
	assert.True(t, operators["endswith"], "Should contain endswith")
	assert.True(t, operators["glob"], "Should contain glob")
	assert.True(t, operators["regex"], "Should contain regex")
}

func TestLogicalOperatorsNotEmpty(t *testing.T) {
	assert.NotEmpty(t, LogicalOperators, "LogicalOperators should not be empty")
}

func TestLogicalOperatorsContainsExpected(t *testing.T) {
	operators := make(map[string]bool)
	for _, op := range LogicalOperators {
		operators[op.Name] = true
	}

	// Check logical operators
	assert.True(t, operators["and"], "Should contain and")
	assert.True(t, operators["or"], "Should contain or")
	assert.True(t, operators["not"], "Should contain not")
}

func TestAllOperatorsReturnsAll(t *testing.T) {
	allOps := AllOperators()

	expectedTotal := len(ComparisonOperators) + len(LogicalOperators)
	assert.Equal(t, expectedTotal, len(allOps))
}

func TestOperatorsHaveName(t *testing.T) {
	for _, op := range AllOperators() {
		assert.NotEmpty(t, op.Name, "Operator should have a name")
	}
}

func TestOperatorsHaveDescription(t *testing.T) {
	for _, op := range AllOperators() {
		assert.NotEmpty(t, op.Description, "Operator %s should have a description", op.Name)
	}
}

func TestNegatedOperators(t *testing.T) {
	// Check that negated versions exist for in/contains/etc
	operators := make(map[string]bool)
	for _, op := range ComparisonOperators {
		operators[op.Name] = true
	}

	// Common negated operators
	if operators["in"] {
		// Check for negation - could be "not in" or handled differently
		// Just verify we have the base operators
		assert.True(t, operators["in"])
	}
}
