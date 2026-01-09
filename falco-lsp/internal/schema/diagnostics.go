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

// DiagnosticCode represents a unique diagnostic code.
type DiagnosticCode string

// Diagnostic code constants for validation errors and warnings.
const (
	// Reference errors.
	DiagUndefinedMacro DiagnosticCode = "undefined-macro"
	DiagUndefinedList  DiagnosticCode = "undefined-list"
	DiagUndefinedRule  DiagnosticCode = "undefined-rule"

	// Duplicate definition errors.
	DiagDuplicateMacro DiagnosticCode = "duplicate-macro"
	DiagDuplicateList  DiagnosticCode = "duplicate-list"
	DiagDuplicateRule  DiagnosticCode = "duplicate-rule"

	// Source mismatch errors.
	DiagWrongSource DiagnosticCode = "wrong-source"

	// Field errors.
	DiagInvalidField    DiagnosticCode = "invalid-field"
	DiagUnknownField    DiagnosticCode = "unknown-field"
	DiagMissingArgument DiagnosticCode = "missing-argument"

	// Syntax errors.
	DiagSyntaxError DiagnosticCode = "syntax-error"

	// Priority errors.
	DiagInvalidPriority DiagnosticCode = "invalid-priority"

	// Property errors.
	DiagMissingRequired      DiagnosticCode = "missing-required"
	DiagUnknownProperty      DiagnosticCode = "unknown-property"
	DiagInvalidPropertyValue DiagnosticCode = "invalid-property-value"
)

// String returns the string representation of the diagnostic code.
func (d DiagnosticCode) String() string {
	return string(d)
}

// AllDiagnosticCodes returns all defined diagnostic codes.
func AllDiagnosticCodes() []DiagnosticCode {
	return []DiagnosticCode{
		DiagUndefinedMacro,
		DiagUndefinedList,
		DiagUndefinedRule,
		DiagDuplicateMacro,
		DiagDuplicateList,
		DiagDuplicateRule,
		DiagWrongSource,
		DiagInvalidField,
		DiagUnknownField,
		DiagMissingArgument,
		DiagSyntaxError,
		DiagInvalidPriority,
		DiagMissingRequired,
		DiagUnknownProperty,
		DiagInvalidPropertyValue,
	}
}
