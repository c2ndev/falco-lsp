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

// BlockType represents a Falco rule file block type.
type BlockType string

// Block type constants for Falco rule files.
const (
	BlockRule      BlockType = "rule"
	BlockMacro     BlockType = "macro"
	BlockList      BlockType = "list"
	BlockException BlockType = "exception"
	BlockTop       BlockType = "top" // Top-level context (not inside any block)
)

// String returns the string representation of the block type.
func (b BlockType) String() string {
	return string(b)
}

// AllBlockTypes returns all valid block types (excluding top-level).
func AllBlockTypes() []BlockType {
	return []BlockType{
		BlockRule,
		BlockMacro,
		BlockList,
	}
}

// IsValidBlockType checks if the given string is a valid top-level block type.
// Exception and top are internal types, not valid for top-level blocks.
func IsValidBlockType(s string) bool {
	switch BlockType(s) {
	case BlockRule, BlockMacro, BlockList:
		return true
	case BlockException, BlockTop:
		return false
	default:
		return false
	}
}

// ExceptionContext represents a context within an exception block.
type ExceptionContext string

// Exception context constants.
const (
	ExceptionContextName   ExceptionContext = "exception_name"
	ExceptionContextFields ExceptionContext = "exception_fields"
	ExceptionContextComps  ExceptionContext = "exception_comps"
	ExceptionContextValues ExceptionContext = "exception_values"
)

// String returns the string representation of the exception context.
func (e ExceptionContext) String() string {
	return string(e)
}

// AllExceptionContexts returns all exception contexts.
func AllExceptionContexts() []ExceptionContext {
	return []ExceptionContext{
		ExceptionContextName,
		ExceptionContextFields,
		ExceptionContextComps,
		ExceptionContextValues,
	}
}
