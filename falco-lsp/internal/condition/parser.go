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

package condition

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/falcosecurity/falco-lsp/internal/ast"
	"github.com/falcosecurity/falco-lsp/internal/lexer"
)

// ParseError represents a parsing error with location information.
type ParseError struct {
	Message string
	Pos     ast.Position
	Range   ast.Range
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("line %d, col %d: %s", e.Pos.Line, e.Pos.Column, e.Message)
}

// ParseResult contains the result of parsing a condition expression.
type ParseResult struct {
	Expression ast.Expression
	Errors     []ParseError
}

// Parser parses Falco condition expressions.
type Parser struct {
	tokens  []lexer.Token
	current int
	errors  []ParseError
	source  string
}

var numberRegex = regexp.MustCompile(`^-?\d+(\.\d+)?$`)

// Parse parses a condition expression and returns the AST.
func Parse(source string) *ParseResult {
	tokens := lexer.Tokenize(source)

	p := &Parser{
		tokens: tokens,
		source: source,
	}

	expr := p.parseExpression()

	return &ParseResult{
		Expression: expr,
		Errors:     p.errors,
	}
}

// parseExpression parses a full expression (handles 'or' with lowest precedence).
func (p *Parser) parseExpression() ast.Expression {
	return p.parseOr()
}

// parseOr parses 'or' expressions.
func (p *Parser) parseOr() ast.Expression {
	left := p.parseAnd()

	for p.peekLower() == ast.OpOr.String() {
		p.advance() // consume 'or'
		right := p.parseAnd()
		left = &ast.BinaryExpr{
			Range: ast.Range{
				Start: left.Pos().Start,
				End:   right.Pos().End,
			},
			Left:     left,
			Operator: ast.OpOr,
			Right:    right,
		}
	}

	return left
}

// parseAnd parses 'and' expressions.
func (p *Parser) parseAnd() ast.Expression {
	left := p.parseUnary()

	for p.peekLower() == ast.OpAnd.String() {
		p.advance() // consume 'and'
		right := p.parseUnary()
		left = &ast.BinaryExpr{
			Range: ast.Range{
				Start: left.Pos().Start,
				End:   right.Pos().End,
			},
			Left:     left,
			Operator: ast.OpAnd,
			Right:    right,
		}
	}

	return left
}

// parseUnary parses 'not' and 'exists' expressions.
func (p *Parser) parseUnary() ast.Expression {
	token := p.peekLower()

	if token == ast.OpNot.String() {
		notTok := p.advance()
		operand := p.parseUnary() // Right-associative
		return &ast.UnaryExpr{
			Range: ast.Range{
				Start: notTok.Pos,
				End:   operand.Pos().End,
			},
			Operator: ast.OpNot,
			Operand:  operand,
		}
	}

	// Note: 'exists' is handled differently in TypeScript - as prefix
	// but in Falco it can be both prefix and postfix. Handle as prefix here.
	if token == ast.OpExists.String() {
		existsTok := p.advance()
		operand := p.parsePrimary()
		return &ast.UnaryExpr{
			Range: ast.Range{
				Start: existsTok.Pos,
				End:   operand.Pos().End,
			},
			Operator: ast.OpExists,
			Operand:  operand,
		}
	}

	return p.parseComparison()
}

// parseComparison parses comparison expressions.
func (p *Parser) parseComparison() ast.Expression {
	left := p.parsePrimary()

	token := p.peekLower()
	if token == "" {
		return left
	}

	// Handle postfix 'exists': field exists
	if token == ast.OpExists.String() {
		existsTok := p.advance()
		return &ast.UnaryExpr{
			Range: ast.Range{
				Start: left.Pos().Start,
				End:   existsTok.Pos,
			},
			Operator: ast.OpExists,
			Operand:  left,
		}
	}

	// Check for comparison operators
	isCompOp := ast.IsComparisonOperator(token)

	if isCompOp {
		opTok := p.advance()
		operator := ast.NewOperator(opTok.Value)
		right := p.parseComparisonRHS(operator)
		return &ast.BinaryExpr{
			Range: ast.Range{
				Start: left.Pos().Start,
				End:   right.Pos().End,
			},
			Left:     left,
			Operator: operator,
			Right:    right,
		}
	}

	return left
}

// parseComparisonRHS parses the right-hand side of a comparison.
func (p *Parser) parseComparisonRHS(operator ast.Operator) ast.Expression {
	tok := p.peek()

	// Inline list: (item1, item2, ...)
	if tok.Type == lexer.TokenLParen {
		return p.parseTuple()
	}

	// For 'in' and 'intersects' operators without parentheses, treat as list reference
	if (operator == ast.OpIn || operator == ast.OpIntersects) && tok.Type == lexer.TokenWord {
		value := tok.Value
		lower := strings.ToLower(value)

		// Don't consume logical operators or comparison operators
		if ast.IsLogicalOperator(lower) || ast.IsComparisonOperator(lower) {
			return p.errorExpr("expected list name")
		}

		// It's a list reference
		p.advance()
		return &ast.ListRef{
			Range: tok.Range,
			Name:  value,
		}
	}

	// On the RHS of a comparison, treat unquoted values as string literals
	// even if they contain dots (e.g., proc.pname=beam.smp -> beam.smp is a string)
	// The only exception is numeric literals
	if tok.Type == lexer.TokenWord {
		value := tok.Value
		lower := strings.ToLower(value)

		// Don't consume logical operators or comparison operators
		if ast.IsLogicalOperator(lower) || ast.IsComparisonOperator(lower) {
			return p.errorExpr("expected value")
		}

		// Check if it's a number
		if numberRegex.MatchString(value) {
			p.advance()
			val, err := strconv.ParseFloat(value, 64)
			if err != nil {
				// If parsing fails, treat as string literal
				return &ast.StringLiteral{
					Range:  tok.Range,
					Value:  value,
					Quoted: false,
				}
			}
			return &ast.NumberLiteral{
				Range: tok.Range,
				Value: val,
				Raw:   value,
				IsInt: !strings.Contains(value, "."),
			}
		}

		// Treat as string literal (even if it contains dots)
		p.advance()
		return &ast.StringLiteral{
			Range:  tok.Range,
			Value:  value,
			Quoted: false,
		}
	}

	return p.parsePrimary()
}

// parseTuple parses a tuple literal: (item1, item2, ...)
func (p *Parser) parseTuple() ast.Expression {
	startTok := p.advance() // consume '('
	elements := []ast.Expression{}

	for !p.check(lexer.TokenRParen) && !p.isAtEnd() {
		// Skip commas
		if p.check(lexer.TokenComma) {
			p.advance()
			continue
		}

		elem := p.parseTupleElement()
		elements = append(elements, elem)
	}

	if !p.check(lexer.TokenRParen) {
		p.error("expected ')' after tuple elements")
		return p.errorExpr("expected ')'")
	}
	endTok := p.advance() // consume ')'

	return &ast.TupleExpr{
		Range: ast.Range{
			Start: startTok.Pos,
			End:   endTok.Range.End,
		},
		Elements: elements,
	}
}

// parseTupleElement parses an element inside a tuple.
func (p *Parser) parseTupleElement() ast.Expression {
	tok := p.peek()

	// String literal
	if tok.Type == lexer.TokenString {
		p.advance()
		// Remove quotes from value
		value := tok.Value
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') {
			value = value[1 : len(value)-1]
		}
		return &ast.StringLiteral{
			Range:  tok.Range,
			Value:  value,
			Quoted: true,
		}
	}

	// Number
	if tok.Type == lexer.TokenNumber {
		p.advance()
		val, err := strconv.ParseFloat(tok.Value, 64)
		if err != nil {
			// If parsing fails, treat as string literal
			return &ast.StringLiteral{
				Range:  tok.Range,
				Value:  tok.Value,
				Quoted: false,
			}
		}
		return &ast.NumberLiteral{
			Range: tok.Range,
			Value: val,
			Raw:   tok.Value,
			IsInt: !strings.Contains(tok.Value, "."),
		}
	}

	// Word (identifier or unquoted string value)
	if tok.Type == lexer.TokenWord {
		p.advance()
		return &ast.StringLiteral{
			Range:  tok.Range,
			Value:  tok.Value,
			Quoted: false,
		}
	}

	p.error(fmt.Sprintf("unexpected token in tuple: %s", tok.Value))
	return p.errorExpr("unexpected token in tuple")
}

// parsePrimary parses a primary expression.
func (p *Parser) parsePrimary() ast.Expression {
	tok := p.peek()

	if tok.Type == lexer.TokenEOF {
		return p.errorExpr("unexpected end of expression")
	}

	// Don't consume closing paren - let the caller handle it
	if tok.Type == lexer.TokenRParen {
		return p.errorExpr("unexpected ')'")
	}

	// Parenthesized expression
	if tok.Type == lexer.TokenLParen {
		startTok := p.advance() // consume '('
		expr := p.parseOr()
		if p.check(lexer.TokenRParen) {
			endTok := p.advance() // consume ')'
			return &ast.ParenExpr{
				Range: ast.Range{
					Start: startTok.Pos,
					End:   endTok.Range.End,
				},
				Expr: expr,
			}
		}
		p.error("expected ')' after expression")
		return expr
	}

	// String literal
	if tok.Type == lexer.TokenString {
		p.advance()
		// Remove quotes from value
		value := tok.Value
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') {
			value = value[1 : len(value)-1]
		}
		return &ast.StringLiteral{
			Range:  tok.Range,
			Value:  value,
			Quoted: true,
		}
	}

	// Number
	if tok.Type == lexer.TokenNumber {
		p.advance()
		val, err := strconv.ParseFloat(tok.Value, 64)
		if err != nil {
			// If parsing fails, treat as string literal
			return &ast.StringLiteral{
				Range:  tok.Range,
				Value:  tok.Value,
				Quoted: false,
			}
		}
		return &ast.NumberLiteral{
			Range: tok.Range,
			Value: val,
			Raw:   tok.Value,
			IsInt: !strings.Contains(tok.Value, "."),
		}
	}

	// Word (field, macro, keyword)
	if tok.Type == lexer.TokenWord {
		p.advance()
		return p.parseFieldOrMacro(&tok)
	}

	// Operator used as value (like < or >)
	if tok.Type == lexer.TokenOperator {
		p.advance()
		return &ast.StringLiteral{
			Range:  tok.Range,
			Value:  tok.Value,
			Quoted: false,
		}
	}

	p.advance()
	p.error(fmt.Sprintf("unexpected token: %s", tok.Value))
	return p.errorExpr(fmt.Sprintf("unexpected token: %s", tok.Value))
}

// parseFieldOrMacro determines if an identifier is a field or macro reference.
func (p *Parser) parseFieldOrMacro(tok *lexer.Token) ast.Expression {
	name := tok.Value

	// Fields contain dots (e.g., proc.name, fd.directory)
	if strings.Contains(name, ".") {
		return p.parseFieldExpr(tok)
	}

	// Check for boolean literals
	lower := strings.ToLower(name)
	if lower == "true" {
		return &ast.BoolLiteral{
			Range: tok.Range,
			Value: true,
		}
	}
	if lower == "false" {
		return &ast.BoolLiteral{
			Range: tok.Range,
			Value: false,
		}
	}

	// Otherwise, treat as macro reference
	return &ast.MacroRef{
		Range: tok.Range,
		Name:  name,
	}
}

// parseFieldExpr parses a field expression from a token.
func (p *Parser) parseFieldExpr(tok *lexer.Token) *ast.FieldExpr {
	name := tok.Value
	arg := ""

	// Check for bracket argument (e.g., proc.aname[1])
	if idx := strings.Index(name, "["); idx != -1 {
		endIdx := strings.Index(name, "]")
		if endIdx > idx {
			arg = name[idx+1 : endIdx]
			name = name[:idx]
		}
	}

	return &ast.FieldExpr{
		Range:    tok.Range,
		Name:     name,
		Argument: arg,
	}
}

// Helper methods

func (p *Parser) peek() lexer.Token {
	if p.current >= len(p.tokens) {
		return lexer.Token{Type: lexer.TokenEOF}
	}
	return p.tokens[p.current]
}

func (p *Parser) peekLower() string {
	tok := p.peek()
	if tok.Type == lexer.TokenEOF {
		return ""
	}
	return strings.ToLower(tok.Value)
}

func (p *Parser) advance() lexer.Token {
	if !p.isAtEnd() {
		p.current++
	}
	return p.previous()
}

func (p *Parser) previous() lexer.Token {
	if p.current == 0 {
		return lexer.Token{}
	}
	return p.tokens[p.current-1]
}

func (p *Parser) check(t lexer.TokenType) bool {
	if p.isAtEnd() {
		return false
	}
	return p.peek().Type == t
}

func (p *Parser) isAtEnd() bool {
	return p.peek().Type == lexer.TokenEOF
}

func (p *Parser) error(message string) {
	pos := p.peek().Pos
	p.errors = append(p.errors, ParseError{
		Message: message,
		Pos:     pos,
		Range: ast.Range{
			Start: pos,
			End:   pos,
		},
	})
}

func (p *Parser) errorExpr(message string) *ast.ErrorExpr {
	pos := p.peek().Pos
	return &ast.ErrorExpr{
		Range: ast.Range{
			Start: pos,
			End:   pos,
		},
		Message: message,
	}
}
