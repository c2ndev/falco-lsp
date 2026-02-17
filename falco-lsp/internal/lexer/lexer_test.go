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

func TestTokenizeStringWithEscapeSequences(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"newline", `"hello\nworld"`, "hello\nworld"},
		{"tab", `"hello\tworld"`, "hello\tworld"},
		{"carriage return", `"hello\rworld"`, "hello\rworld"},
		{"backslash", `"hello\\world"`, "hello\\world"},
		{"double quote", `"hello\"world"`, "hello\"world"},
		{"single quote in double", `"hello\'world"`, "hello'world"},
		{"unknown escape", `"hello\xworld"`, "helloxworld"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := Tokenize(tt.input)
			require.GreaterOrEqual(t, len(tokens), 2)
			assert.Equal(t, TokenString, tokens[0].Type)
			assert.Equal(t, tt.expected, tokens[0].Value)
		})
	}
}

func TestTokenizeSingleQuotedStringWithEscapes(t *testing.T) {
	input := `'hello\nworld'`
	tokens := Tokenize(input)
	require.GreaterOrEqual(t, len(tokens), 2)
	assert.Equal(t, TokenString, tokens[0].Type)
	assert.Equal(t, "hello\nworld", tokens[0].Value)
}

func TestTokenTypeString(t *testing.T) {
	tests := []struct {
		tokenType TokenType
		expected  string
	}{
		{TokenEOF, "EOF"},
		{TokenError, "ERROR"},
		{TokenWord, "WORD"},
		{TokenNumber, "NUMBER"},
		{TokenString, "STRING"},
		{TokenLParen, "LPAREN"},
		{TokenRParen, "RPAREN"},
		{TokenLBrack, "LBRACK"},
		{TokenRBrack, "RBRACK"},
		{TokenLBrace, "LBRACE"},
		{TokenRBrace, "RBRACE"},
		{TokenComma, "COMMA"},
		{TokenDot, "DOT"},
		{TokenOperator, "OPERATOR"},
		{TokenType(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.tokenType.String())
		})
	}
}
