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
	"regexp"
	"unicode"

	"github.com/c2ndev/falco-lsp/internal/ast"
)

// TokenType represents the type of a token.
type TokenType int

const (
	// TokenEOF represents end of file.
	TokenEOF TokenType = iota
	// TokenError represents a lexical error.
	TokenError

	// TokenWord represents an identifier, field, keyword, or operator keyword.
	TokenWord
	// TokenNumber represents a numeric literal.
	TokenNumber
	// TokenString represents a quoted string.
	TokenString

	// TokenLParen represents a left parenthesis '('.
	TokenLParen
	// TokenRParen represents a right parenthesis ')'.
	TokenRParen
	// TokenLBrack represents a left bracket '['.
	TokenLBrack
	// TokenRBrack represents a right bracket ']'.
	TokenRBrack
	// TokenLBrace represents a left brace '{'.
	TokenLBrace
	// TokenRBrace represents a right brace '}'.
	TokenRBrace
	// TokenComma represents a comma ','.
	TokenComma
	// TokenDot represents a dot '.'.
	TokenDot
	// TokenOperator represents an operator (=, ==, !=, <, <=, >, >=).
	TokenOperator
)

var tokenTypeNames = map[TokenType]string{
	TokenEOF:      "EOF",
	TokenError:    "ERROR",
	TokenWord:     "WORD",
	TokenNumber:   "NUMBER",
	TokenString:   "STRING",
	TokenLParen:   "LPAREN",
	TokenRParen:   "RPAREN",
	TokenLBrack:   "LBRACK",
	TokenRBrack:   "RBRACK",
	TokenLBrace:   "LBRACE",
	TokenRBrace:   "RBRACE",
	TokenComma:    "COMMA",
	TokenDot:      "DOT",
	TokenOperator: "OPERATOR",
}

func (t TokenType) String() string {
	if name, ok := tokenTypeNames[t]; ok {
		return name
	}
	return "UNKNOWN"
}

// Token represents a lexical token.
type Token struct {
	Type  TokenType
	Value string
	Pos   ast.Position
	Range ast.Range
}

// Note: All operator classification functions (IsOperator, IsLogicalOperator,
// IsComparisonOperator, IsUnaryOperator) are defined in the ast package.
// Use ast.IsOperator(), ast.IsLogicalOperator(), etc. directly to avoid unnecessary wrappers.

// wordRegex matches identifiers, fields, fields with index like container.mount.dest[/proc*]
// Pattern includes: letters, digits, _, ., [, ], :, /, -, *, ?, ~
// Compiled at package init to avoid recompilation on every Tokenize call.
var wordRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.\[\]:/*?~-]*`)

// lexerState holds the state during tokenization.
type lexerState struct {
	input     string
	pos       int
	line      int
	lineStart int
}

func (s *lexerState) currentCol() int {
	return s.pos - s.lineStart
}

func (s *lexerState) currentChar() byte {
	return s.input[s.pos]
}

func (s *lexerState) startPosition() ast.Position {
	return ast.Position{Line: s.line, Column: s.currentCol(), Offset: s.pos}
}

func (s *lexerState) endPosition() ast.Position {
	return ast.Position{Line: s.line, Column: s.currentCol(), Offset: s.pos}
}

// Tokenize tokenizes a condition string.
// This mirrors the TypeScript tokenizeCondition function exactly.
func Tokenize(input string) []Token {
	var tokens []Token
	s := &lexerState{
		input:     input,
		pos:       0,
		line:      1,
		lineStart: 0,
	}

	for s.pos < len(input) {
		// Skip whitespace
		if unicode.IsSpace(rune(s.currentChar())) {
			if s.currentChar() == '\n' {
				s.line++
				s.lineStart = s.pos + 1
			}
			s.pos++
			continue
		}

		// Try tokenizers in order
		if tok, ok := s.tokenizeString(); ok {
			tokens = append(tokens, tok)
			continue
		}

		if tok, ok := s.tokenizePunctuation(); ok {
			tokens = append(tokens, tok)
			continue
		}

		if tok, ok := s.tokenizeMultiCharOperator(); ok {
			tokens = append(tokens, tok)
			continue
		}

		if tok, ok := s.tokenizeSingleCharOperator(); ok {
			tokens = append(tokens, tok)
			continue
		}

		if tok, ok := s.tokenizePath(); ok {
			tokens = append(tokens, tok)
			continue
		}

		if tok, ok := s.tokenizeWord(); ok {
			tokens = append(tokens, tok)
			continue
		}

		if tok, ok := s.tokenizeNumber(); ok {
			tokens = append(tokens, tok)
			continue
		}

		// Unknown character - skip
		s.pos++
	}

	// Add EOF
	tokens = append(tokens, Token{
		Type:  TokenEOF,
		Value: "",
		Pos:   s.endPosition(),
		Range: ast.Range{Start: s.endPosition(), End: s.endPosition()},
	})

	return tokens
}

// tokenizeString handles quoted string literals.
func (s *lexerState) tokenizeString() (Token, bool) {
	if s.currentChar() != '"' && s.currentChar() != '\'' {
		return Token{}, false
	}

	startPos := s.startPosition()
	quote := s.currentChar()
	str := ""
	s.pos++ // skip opening quote

	for s.pos < len(s.input) && s.input[s.pos] != quote {
		if s.input[s.pos] == '\\' && s.pos+1 < len(s.input) {
			str += parseEscapeSequence(s.input[s.pos+1])
			s.pos += 2
		} else {
			str += string(s.input[s.pos])
			s.pos++
		}
	}
	if s.pos < len(s.input) {
		s.pos++ // skip closing quote
	}

	return Token{
		Type:  TokenString,
		Value: str,
		Pos:   startPos,
		Range: ast.Range{Start: startPos, End: s.endPosition()},
	}, true
}

// parseEscapeSequence converts an escape character to its actual value.
func parseEscapeSequence(c byte) string {
	switch c {
	case 'n':
		return "\n"
	case 't':
		return "\t"
	case 'r':
		return "\r"
	case '\\':
		return "\\"
	case '"':
		return "\""
	case '\'':
		return "'"
	default:
		return string(c)
	}
}

// tokenizePunctuation handles parentheses, braces, and commas.
func (s *lexerState) tokenizePunctuation() (Token, bool) {
	startPos := s.startPosition()
	c := s.currentChar()

	var typ TokenType
	switch c {
	case '(':
		typ = TokenLParen
	case ')':
		typ = TokenRParen
	case '{':
		typ = TokenLBrace
	case '}':
		typ = TokenRBrace
	case ',':
		typ = TokenComma
	default:
		return Token{}, false
	}

	s.pos++
	return Token{
		Type:  typ,
		Value: string(c),
		Pos:   startPos,
		Range: ast.Range{Start: startPos, End: s.endPosition()},
	}, true
}

// tokenizeMultiCharOperator handles ==, !=, <=, >=.
func (s *lexerState) tokenizeMultiCharOperator() (Token, bool) {
	if s.pos+1 >= len(s.input) {
		return Token{}, false
	}

	startPos := s.startPosition()
	two := s.input[s.pos : s.pos+2]

	if two != "==" && two != "!=" && two != "<=" && two != ">=" {
		return Token{}, false
	}

	s.pos += 2
	return Token{
		Type:  TokenOperator,
		Value: two,
		Pos:   startPos,
		Range: ast.Range{Start: startPos, End: s.endPosition()},
	}, true
}

// tokenizeSingleCharOperator handles =, <, >.
func (s *lexerState) tokenizeSingleCharOperator() (Token, bool) {
	c := s.currentChar()
	if c != '=' && c != '<' && c != '>' {
		return Token{}, false
	}

	startPos := s.startPosition()
	s.pos++
	return Token{
		Type:  TokenOperator,
		Value: string(c),
		Pos:   startPos,
		Range: ast.Range{Start: startPos, End: s.endPosition()},
	}, true
}

// tokenizePath handles Unix paths starting with /.
func (s *lexerState) tokenizePath() (Token, bool) {
	if s.currentChar() != '/' {
		return Token{}, false
	}

	startPos := s.startPosition()
	path := ""
	for s.pos < len(s.input) && isPathChar(rune(s.input[s.pos])) {
		path += string(s.input[s.pos])
		s.pos++
	}

	if path == "" {
		return Token{}, false
	}

	return Token{
		Type:  TokenWord,
		Value: path,
		Pos:   startPos,
		Range: ast.Range{Start: startPos, End: s.endPosition()},
	}, true
}

// tokenizeWord handles identifiers, keywords, and fields.
func (s *lexerState) tokenizeWord() (Token, bool) {
	c := rune(s.currentChar())
	if !unicode.IsLetter(c) && c != '_' {
		return Token{}, false
	}

	startPos := s.startPosition()
	match := wordRegex.FindString(s.input[s.pos:])
	if match == "" {
		return Token{}, false
	}

	s.pos += len(match)
	return Token{
		Type:  TokenWord,
		Value: match,
		Pos:   startPos,
		Range: ast.Range{Start: startPos, End: s.endPosition()},
	}, true
}

// tokenizeNumber handles numeric literals including negative numbers.
func (s *lexerState) tokenizeNumber() (Token, bool) {
	c := s.currentChar()
	isNegative := c == '-' && s.pos+1 < len(s.input) && unicode.IsDigit(rune(s.input[s.pos+1]))
	if !unicode.IsDigit(rune(c)) && !isNegative {
		return Token{}, false
	}

	startPos := s.startPosition()
	num := ""

	if c == '-' {
		num += string(c)
		s.pos++
	}

	for s.pos < len(s.input) && (unicode.IsDigit(rune(s.input[s.pos])) || s.input[s.pos] == '.') {
		num += string(s.input[s.pos])
		s.pos++
	}

	return Token{
		Type:  TokenNumber,
		Value: num,
		Pos:   startPos,
		Range: ast.Range{Start: startPos, End: s.endPosition()},
	}, true
}

func isPathChar(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) ||
		r == '/' || r == '_' || r == '.' || r == '-' ||
		r == '~' || r == '*' || r == '?' || r == '[' || r == ']'
}
