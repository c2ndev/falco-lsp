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

package schema

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiagnosticCodeString(t *testing.T) {
	tests := []struct {
		code     DiagnosticCode
		expected string
	}{
		{DiagUndefinedMacro, "undefined-macro"},
		{DiagUndefinedList, "undefined-list"},
		{DiagUndefinedRule, "undefined-rule"},
		{DiagDuplicateMacro, "duplicate-macro"},
		{DiagDuplicateList, "duplicate-list"},
		{DiagDuplicateRule, "duplicate-rule"},
		{DiagWrongSource, "wrong-source"},
		{DiagInvalidField, "invalid-field"},
		{DiagUnknownField, "unknown-field"},
		{DiagMissingArgument, "missing-argument"},
		{DiagSyntaxError, "syntax-error"},
		{DiagInvalidPriority, "invalid-priority"},
		{DiagMissingRequired, "missing-required"},
		{DiagUnknownProperty, "unknown-property"},
		{DiagInvalidPropertyValue, "invalid-property-value"},
	}

	for _, tt := range tests {
		t.Run(string(tt.code), func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.code.String())
		})
	}
}

func TestAllDiagnosticCodes(t *testing.T) {
	codes := AllDiagnosticCodes()

	// Verify all codes are included
	assert.Len(t, codes, 15)

	// Verify uniqueness
	seen := make(map[DiagnosticCode]bool)
	for _, code := range codes {
		assert.False(t, seen[code], "Duplicate code: %s", code)
		seen[code] = true
	}
}

func TestDiagnosticCodesAreUnique(t *testing.T) {
	codes := AllDiagnosticCodes()

	// Verify string values are unique
	seen := make(map[string]bool)
	for _, code := range codes {
		str := code.String()
		assert.False(t, seen[str], "Duplicate code string: %s", str)
		seen[str] = true
	}
}

func TestDiagnosticCodesContainsExpected(t *testing.T) {
	codes := AllDiagnosticCodes()
	codeSet := make(map[DiagnosticCode]bool)
	for _, c := range codes {
		codeSet[c] = true
	}

	// Reference errors
	assert.True(t, codeSet[DiagUndefinedMacro])
	assert.True(t, codeSet[DiagUndefinedList])
	assert.True(t, codeSet[DiagUndefinedRule])

	// Duplicate errors
	assert.True(t, codeSet[DiagDuplicateMacro])
	assert.True(t, codeSet[DiagDuplicateList])
	assert.True(t, codeSet[DiagDuplicateRule])

	// Field errors
	assert.True(t, codeSet[DiagWrongSource])
	assert.True(t, codeSet[DiagInvalidField])
	assert.True(t, codeSet[DiagUnknownField])
	assert.True(t, codeSet[DiagMissingArgument])
}
