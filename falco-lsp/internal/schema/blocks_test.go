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

func TestBlockTypeString(t *testing.T) {
	tests := []struct {
		block    BlockType
		expected string
	}{
		{BlockRule, "rule"},
		{BlockMacro, "macro"},
		{BlockList, "list"},
		{BlockException, "exception"},
		{BlockTop, "top"},
	}

	for _, tt := range tests {
		t.Run(string(tt.block), func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.block.String())
		})
	}
}

func TestAllBlockTypes(t *testing.T) {
	blocks := AllBlockTypes()

	assert.Len(t, blocks, 3)
	assert.Contains(t, blocks, BlockRule)
	assert.Contains(t, blocks, BlockMacro)
	assert.Contains(t, blocks, BlockList)
	// BlockException and BlockTop are not in AllBlockTypes as they are not top-level blocks
	assert.NotContains(t, blocks, BlockException)
	assert.NotContains(t, blocks, BlockTop)
}

func TestIsValidBlockType(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"rule", true},
		{"macro", true},
		{"list", true},
		{"exception", false}, // Not a top-level block type
		{"top", false},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsValidBlockType(tt.input))
		})
	}
}

func TestExceptionContextString(t *testing.T) {
	tests := []struct {
		ctx      ExceptionContext
		expected string
	}{
		{ExceptionContextName, "exception_name"},
		{ExceptionContextFields, "exception_fields"},
		{ExceptionContextComps, "exception_comps"},
		{ExceptionContextValues, "exception_values"},
	}

	for _, tt := range tests {
		t.Run(string(tt.ctx), func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.ctx.String())
		})
	}
}

func TestAllExceptionContexts(t *testing.T) {
	contexts := AllExceptionContexts()

	assert.Len(t, contexts, 4)
	assert.Contains(t, contexts, ExceptionContextName)
	assert.Contains(t, contexts, ExceptionContextFields)
	assert.Contains(t, contexts, ExceptionContextComps)
	assert.Contains(t, contexts, ExceptionContextValues)
}
