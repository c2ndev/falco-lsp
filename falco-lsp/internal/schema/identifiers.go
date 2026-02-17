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

// Identifier character classification for Falco rule syntax.
// These functions define what characters are valid in different contexts.

// IsIdentifierChar returns true if r is a valid character in a Falco identifier.
// This includes alphanumeric characters and underscore.
// Used for: macro names, list names, rule names (without spaces).
func IsIdentifierChar(r rune) bool {
	return (r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9') ||
		r == '_'
}

// IsIdentifierCharByte is the byte version of IsIdentifierChar for ASCII-only contexts.
func IsIdentifierCharByte(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '_'
}

// IsFieldChar returns true if r is a valid character in a Falco field name.
// Fields can contain dots for nested access and brackets for indexing.
// Used for: proc.name, container.id, evt.args[0], ka.target.name.
func IsFieldChar(r rune) bool {
	return IsIdentifierChar(r) ||
		r == '.' ||
		r == '[' ||
		r == ']'
}

// IsWordChar returns true if r is a valid word character for general text contexts.
// This is used by the completion and hover providers to identify word boundaries.
// Includes dash (-) for completions like MITER tags (miter-attack, T1059.001).
func IsWordChar(r rune) bool {
	return IsIdentifierChar(r) ||
		r == '.' ||
		r == '-'
}

// IsWordCharByte is the byte version of IsWordChar for ASCII-only contexts.
func IsWordCharByte(c byte) bool {
	return IsIdentifierCharByte(c) ||
		c == '.' ||
		c == '-'
}
