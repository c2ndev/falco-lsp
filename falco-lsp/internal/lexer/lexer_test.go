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

package lexer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenizeSimpleCondition(t *testing.T) {
	input := `proc.name = bash`
	tokens := Tokenize(input)

	require.GreaterOrEqual(t, len(tokens), 4) // WORD, OPERATOR, WORD, EOF
	assert.Equal(t, TokenWord, tokens[0].Type)
	assert.Equal(t, "proc.name", tokens[0].Value)
	assert.Equal(t, TokenOperator, tokens[1].Type)
	assert.Equal(t, "=", tokens[1].Value)
	assert.Equal(t, TokenWord, tokens[2].Type)
	assert.Equal(t, "bash", tokens[2].Value)
	assert.Equal(t, TokenEOF, tokens[len(tokens)-1].Type)
}

func TestTokenizeWithOperators(t *testing.T) {
	input := `proc.name = bash and fd.name contains /etc`
	tokens := Tokenize(input)

	// Should have: proc.name, =, bash, and, fd.name, contains, /etc, EOF
	require.GreaterOrEqual(t, len(tokens), 8)

	// Verify key tokens
	assert.Equal(t, "proc.name", tokens[0].Value)
	assert.Equal(t, "=", tokens[1].Value)
	assert.Equal(t, "bash", tokens[2].Value)
	assert.Equal(t, "and", tokens[3].Value)
	assert.Equal(t, "fd.name", tokens[4].Value)
	assert.Equal(t, "contains", tokens[5].Value)
}

func TestTokenizeQuotedStrings(t *testing.T) {
	input := `proc.cmdline contains "rm -rf /"`
	tokens := Tokenize(input)

	require.GreaterOrEqual(t, len(tokens), 4)
	assert.Equal(t, TokenWord, tokens[0].Type)
	assert.Equal(t, TokenWord, tokens[1].Type) // "contains" is a word
	assert.Equal(t, TokenString, tokens[2].Type)
	assert.Equal(t, "rm -rf /", tokens[2].Value) // Without quotes
}

func TestTokenizeParentheses(t *testing.T) {
	input := `(proc.name = bash or proc.name = sh)`
	tokens := Tokenize(input)

	assert.Equal(t, TokenLParen, tokens[0].Type)
	assert.Equal(t, TokenRParen, tokens[len(tokens)-2].Type)
}

func TestTokenizeInOperator(t *testing.T) {
	input := `proc.name in (bash, sh, zsh)`
	tokens := Tokenize(input)

	// Should have: proc.name, in, (, bash, ,, sh, ,, zsh, ), EOF
	require.GreaterOrEqual(t, len(tokens), 10)

	assert.Equal(t, TokenWord, tokens[0].Type)   // proc.name
	assert.Equal(t, TokenWord, tokens[1].Type)   // in
	assert.Equal(t, TokenLParen, tokens[2].Type) // (
	assert.Equal(t, TokenWord, tokens[3].Type)   // bash
	assert.Equal(t, TokenComma, tokens[4].Type)  // ,
	assert.Equal(t, TokenWord, tokens[5].Type)   // sh
	assert.Equal(t, TokenComma, tokens[6].Type)  // ,
	assert.Equal(t, TokenWord, tokens[7].Type)   // zsh
	assert.Equal(t, TokenRParen, tokens[8].Type) // )
	assert.Equal(t, TokenEOF, tokens[9].Type)
}

func TestTokenizeDynamicField(t *testing.T) {
	input := `proc.aname[2] = systemd`
	tokens := Tokenize(input)

	require.GreaterOrEqual(t, len(tokens), 4)
	assert.Equal(t, TokenWord, tokens[0].Type)
	assert.Equal(t, "proc.aname[2]", tokens[0].Value)
}

func TestTokenizeComparisonOperators(t *testing.T) {
	tests := []struct {
		input string
		op    string
	}{
		{`fd.num >= 0`, ">="},
		{`fd.num <= 10`, "<="},
		{`fd.num != 0`, "!="},
		{`fd.num > 5`, ">"},
		{`fd.num < 100`, "<"},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			tokens := Tokenize(test.input)
			require.GreaterOrEqual(t, len(tokens), 3)
			assert.Equal(t, TokenOperator, tokens[1].Type)
			assert.Equal(t, test.op, tokens[1].Value)
		})
	}
}

func TestTokenizePathValues(t *testing.T) {
	input := `fd.name = /etc/passwd`
	tokens := Tokenize(input)

	require.GreaterOrEqual(t, len(tokens), 4)
	assert.Equal(t, "/etc/passwd", tokens[2].Value)
}

func TestTokenizeNegativeNumber(t *testing.T) {
	input := `fd.num = -1`
	tokens := Tokenize(input)

	require.GreaterOrEqual(t, len(tokens), 4)
	assert.Equal(t, TokenNumber, tokens[2].Type)
	assert.Equal(t, "-1", tokens[2].Value)
}

func TestTokenizeComplexCondition(t *testing.T) {
	input := `proc.pname in (runc:[0:PARENT], runc:[1:CHILD], runc)`
	tokens := Tokenize(input)

	// Should tokenize without errors
	assert.Equal(t, TokenEOF, tokens[len(tokens)-1].Type)

	// Should contain the complex values
	found := false
	for _, tok := range tokens {
		if tok.Value == "runc:[0:PARENT]" {
			found = true
			break
		}
	}
	assert.True(t, found, "should find runc:[0:PARENT] token")
}

// Note: Operator classification tests have been moved to ast_test.go
// since all operator logic is now centralized in the ast package.
// The lexer no longer provides wrapper functions - use ast.IsOperator(),
// ast.IsLogicalOperator(), ast.IsComparisonOperator(), ast.IsUnaryOperator() directly.
