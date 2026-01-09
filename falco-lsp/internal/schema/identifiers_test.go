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

func TestIsIdentifierChar(t *testing.T) {
	tests := []struct {
		r      rune
		expect bool
	}{
		{'a', true},
		{'z', true},
		{'A', true},
		{'Z', true},
		{'0', true},
		{'9', true},
		{'_', true},
		{' ', false},
		{'-', false},
		{'.', false},
		{'[', false},
		{']', false},
		{'=', false},
		{'(', false},
		{')', false},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expect, IsIdentifierChar(tt.r), "IsIdentifierChar(%q)", tt.r)
	}
}

func TestIsIdentifierCharByte(t *testing.T) {
	tests := []struct {
		c      byte
		expect bool
	}{
		{'a', true},
		{'z', true},
		{'A', true},
		{'Z', true},
		{'0', true},
		{'9', true},
		{'_', true},
		{' ', false},
		{'-', false},
		{'.', false},
		{'[', false},
		{']', false},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expect, IsIdentifierCharByte(tt.c), "IsIdentifierCharByte(%q)", tt.c)
	}
}

func TestIsFieldChar(t *testing.T) {
	tests := []struct {
		r      rune
		expect bool
	}{
		{'a', true},
		{'z', true},
		{'A', true},
		{'Z', true},
		{'0', true},
		{'9', true},
		{'_', true},
		{'.', true}, // Field separator
		{'[', true}, // Array index start
		{']', true}, // Array index end
		{' ', false},
		{'-', false},
		{'=', false},
		{'(', false},
		{')', false},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expect, IsFieldChar(tt.r), "IsFieldChar(%q)", tt.r)
	}
}

func TestIsWordChar(t *testing.T) {
	tests := []struct {
		r      rune
		expect bool
	}{
		{'a', true},
		{'z', true},
		{'A', true},
		{'Z', true},
		{'0', true},
		{'9', true},
		{'_', true},
		{'.', true},  // For field-like completions
		{'-', true},  // For MITRE tags like T1059.001-subtechnique
		{'[', false}, // Not included in word chars
		{']', false},
		{' ', false},
		{'=', false},
		{'(', false},
		{')', false},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expect, IsWordChar(tt.r), "IsWordChar(%q)", tt.r)
	}
}

func TestIsWordCharByte(t *testing.T) {
	tests := []struct {
		c      byte
		expect bool
	}{
		{'a', true},
		{'z', true},
		{'A', true},
		{'0', true},
		{'_', true},
		{'.', true},
		{'-', true},
		{' ', false},
		{'[', false},
		{']', false},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expect, IsWordCharByte(tt.c), "IsWordCharByte(%q)", tt.c)
	}
}
