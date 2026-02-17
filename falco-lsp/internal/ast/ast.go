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

package ast

import "strings"

// Position represents a location in source code.
type Position struct {
	Line   int // 1-based line number
	Column int // 0-based column number (UTF-8 byte offset)
	Offset int // 0-based byte offset from start of source
}

// Range represents a span of source code.
type Range struct {
	Start Position
	End   Position
}

// Operator represents a binary or unary operator.
type Operator string

const (
	// OpAnd is the binary logical AND operator.
	OpAnd Operator = "and"
	// OpOr is the binary logical OR operator.
	OpOr Operator = "or"

	// OpNot is the unary logical negation operator.
	OpNot Operator = "not"
	// OpExists is the unary field existence check operator.
	OpExists Operator = "exists"

	// OpEq is the equality comparison operator (=).
	OpEq Operator = "="
	// OpEqEq is the alternative equality comparison operator (==).
	OpEqEq Operator = "=="
	// OpNeq is the inequality comparison operator (!=).
	OpNeq Operator = "!="

	// OpGt is the greater-than comparison operator (>).
	OpGt Operator = ">"
	// OpGte is the greater-than-or-equal comparison operator (>=).
	OpGte Operator = ">="
	// OpLt is the less-than comparison operator (<).
	OpLt Operator = "<"
	// OpLte is the less-than-or-equal comparison operator (<=).
	OpLte Operator = "<="

	// OpIn is the membership test operator.
	OpIn Operator = "in"
	// OpIntersects is the set intersection operator.
	OpIntersects Operator = "intersects"

	// OpContains is the case-sensitive substring match operator.
	OpContains Operator = "contains"
	// OpStartsWith is the case-sensitive prefix match operator.
	OpStartsWith Operator = "startswith"
	// OpEndsWith is the case-sensitive suffix match operator.
	OpEndsWith Operator = "endswith"

	// OpIContains is the case-insensitive substring match operator.
	OpIContains Operator = "icontains"
	// OpIStartsWith is the case-insensitive prefix match operator.
	OpIStartsWith Operator = "istartswith"
	// OpIEndsWith is the case-insensitive suffix match operator.
	OpIEndsWith Operator = "iendswith"

	// OpBContains is the buffer/binary substring match operator.
	OpBContains Operator = "bcontains"
	// OpBStartsWith is the buffer/binary prefix match operator.
	OpBStartsWith Operator = "bstartswith"
	// OpBEndsWith is the buffer/binary suffix match operator.
	OpBEndsWith Operator = "bendswith"

	// OpGlob is the glob pattern matching operator.
	OpGlob Operator = "glob"
	// OpIGlob is the case-insensitive glob pattern matching operator.
	OpIGlob Operator = "iglob"
	// OpRegex is the regular expression matching operator.
	OpRegex Operator = "regex"
	// OpPMatch is the path matching operator.
	OpPMatch Operator = "pmatch"
)

// String returns the string representation of the operator.
func (op Operator) String() string {
	return string(op)
}

// NewOperator converts a string to an Operator type.
// The input is normalized to lowercase to match operator constants.
// This is the canonical way to create Operator values from parsed tokens.
func NewOperator(s string) Operator {
	return Operator(strings.ToLower(s))
}

// Operator type methods - work on typed Operator values

// IsComparison returns true if this is a comparison operator (=, !=, <, >, contains, in, etc.).
// Used by the analyzer to determine if the right side of a binary expression
// should be treated as a value position (for field validation).
func (op Operator) IsComparison() bool {
	switch op {
	case OpEq, OpEqEq, OpNeq, OpGt, OpGte, OpLt, OpLte,
		OpContains, OpIContains, OpBContains,
		OpStartsWith, OpIStartsWith, OpBStartsWith,
		OpEndsWith, OpIEndsWith, OpBEndsWith,
		OpGlob, OpIGlob, OpRegex, OpPMatch,
		OpIn, OpIntersects:
		return true
	case OpAnd, OpOr, OpNot, OpExists:
		// Logical and unary operators are not comparison operators
		return false
	default:
		return false
	}
}

// IsBinaryLogical returns true if this is a binary logical operator (and, or).
// Used to distinguish binary logical operators from unary operators.
func (op Operator) IsBinaryLogical() bool {
	return op == OpAnd || op == OpOr
}

// IsUnary returns true if this is a unary operator (not, exists).
// Used to identify operators that take a single operand.
func (op Operator) IsUnary() bool {
	return op == OpNot || op == OpExists
}

// String-based operator classification functions - work on string tokens
// These are case-insensitive and used by the lexer/parser for token classification.

// IsOperator checks if the given string is any valid operator.
// Returns true for comparison, logical (and, or), and unary (not, exists) operators.
func IsOperator(op string) bool {
	lower := strings.ToLower(op)
	// Try to convert to Operator and check if it's valid
	operator := Operator(lower)
	return operator.IsComparison() || operator.IsBinaryLogical() || operator.IsUnary()
}

// IsComparisonOperator checks if the given string is a comparison operator.
// Used by the parser for token classification.
func IsComparisonOperator(op string) bool {
	return Operator(strings.ToLower(op)).IsComparison()
}

// IsLogicalOperator checks if the given string is a binary logical operator (and, or).
// Used by the parser to avoid consuming logical operators as values.
// Note: "not" is excluded because it's unary, not binary logical.
func IsLogicalOperator(op string) bool {
	return Operator(strings.ToLower(op)).IsBinaryLogical()
}

// IsUnaryOperator checks if the given string is a unary operator (not, exists).
// Used by the parser for token classification.
func IsUnaryOperator(op string) bool {
	return Operator(strings.ToLower(op)).IsUnary()
}

// Node is the interface implemented by all AST nodes.
type Node interface {
	Pos() Range
	nodeType() string
}

// ---------- Expressions ----------

// Expression is the interface for all expression nodes.
type Expression interface {
	Node
	exprNode()
}

// BinaryExpr represents a binary expression (e.g., and, or, =, !=, contains).
type BinaryExpr struct {
	Range    Range
	Left     Expression
	Operator Operator // "and", "or", "=", "!=", ">=", "<=", ">", "<", "in", "contains", etc.
	Right    Expression
}

// Pos returns the source range of the binary expression.
func (e *BinaryExpr) Pos() Range       { return e.Range }
func (e *BinaryExpr) nodeType() string { return "BinaryExpr" }
func (e *BinaryExpr) exprNode()        {}

// UnaryExpr represents a unary expression (e.g., not, exists).
type UnaryExpr struct {
	Range    Range
	Operator Operator // OpNot or OpExists
	Operand  Expression
}

// Pos returns the source range of the unary expression.
func (e *UnaryExpr) Pos() Range       { return e.Range }
func (e *UnaryExpr) nodeType() string { return "UnaryExpr" }
func (e *UnaryExpr) exprNode()        {}

// ParenExpr represents a parenthesized expression.
type ParenExpr struct {
	Range Range
	Expr  Expression
}

// Pos returns the source range of the parenthesized expression.
func (e *ParenExpr) Pos() Range       { return e.Range }
func (e *ParenExpr) nodeType() string { return "ParenExpr" }
func (e *ParenExpr) exprNode()        {}

// FieldExpr represents a field reference (e.g., proc.name, fd.name).
type FieldExpr struct {
	Range    Range
	Name     string // Full field name like "proc.name"
	Argument string // Optional argument for dynamic fields like proc.aname[1]
}

// Pos returns the source range of the field expression.
func (e *FieldExpr) Pos() Range       { return e.Range }
func (e *FieldExpr) nodeType() string { return "FieldExpr" }
func (e *FieldExpr) exprNode()        {}

// MacroRef represents a macro reference.
type MacroRef struct {
	Range Range
	Name  string
}

// Pos returns the source range of the macro reference.
func (e *MacroRef) Pos() Range       { return e.Range }
func (e *MacroRef) nodeType() string { return "MacroRef" }
func (e *MacroRef) exprNode()        {}

// ListRef represents a list reference in an "in" expression.
type ListRef struct {
	Range Range
	Name  string
}

// Pos returns the source range of the list reference.
func (e *ListRef) Pos() Range       { return e.Range }
func (e *ListRef) nodeType() string { return "ListRef" }
func (e *ListRef) exprNode()        {}

// StringLiteral represents a string literal (quoted or unquoted).
type StringLiteral struct {
	Range  Range
	Value  string
	Quoted bool
}

// Pos returns the source range of the string literal.
func (e *StringLiteral) Pos() Range       { return e.Range }
func (e *StringLiteral) nodeType() string { return "StringLiteral" }
func (e *StringLiteral) exprNode()        {}

// NumberLiteral represents a numeric literal.
type NumberLiteral struct {
	Range Range
	Value float64
	Raw   string // Original text representation
	IsInt bool   // True if the number is an integer
}

// Pos returns the source range of the number literal.
func (e *NumberLiteral) Pos() Range       { return e.Range }
func (e *NumberLiteral) nodeType() string { return "NumberLiteral" }
func (e *NumberLiteral) exprNode()        {}

// BoolLiteral represents a boolean literal (true, false).
type BoolLiteral struct {
	Range Range
	Value bool
}

// Pos returns the source range of the boolean literal.
func (e *BoolLiteral) Pos() Range       { return e.Range }
func (e *BoolLiteral) nodeType() string { return "BoolLiteral" }
func (e *BoolLiteral) exprNode()        {}

// TupleExpr represents a tuple/list literal (e.g., (item1, item2, item3)).
type TupleExpr struct {
	Range    Range
	Elements []Expression
}

// Pos returns the source range of the tuple expression.
func (e *TupleExpr) Pos() Range       { return e.Range }
func (e *TupleExpr) nodeType() string { return "TupleExpr" }
func (e *TupleExpr) exprNode()        {}

// ErrorExpr represents a parsing error placeholder.
type ErrorExpr struct {
	Range   Range
	Message string
}

// Pos returns the source range of the error expression.
func (e *ErrorExpr) Pos() Range       { return e.Range }
func (e *ErrorExpr) nodeType() string { return "ErrorExpr" }
func (e *ErrorExpr) exprNode()        {}

// ---------- Visitor Pattern ----------

// Visitor is the interface for visiting AST nodes.
type Visitor interface {
	VisitBinaryExpr(expr *BinaryExpr) interface{}
	VisitUnaryExpr(expr *UnaryExpr) interface{}
	VisitParenExpr(expr *ParenExpr) interface{}
	VisitFieldExpr(expr *FieldExpr) interface{}
	VisitMacroRef(expr *MacroRef) interface{}
	VisitListRef(expr *ListRef) interface{}
	VisitStringLiteral(expr *StringLiteral) interface{}
	VisitNumberLiteral(expr *NumberLiteral) interface{}
	VisitBoolLiteral(expr *BoolLiteral) interface{}
	VisitTupleExpr(expr *TupleExpr) interface{}
	VisitErrorExpr(expr *ErrorExpr) interface{}
}

// Walk traverses an expression tree depth-first.
func Walk(expr Expression, fn func(Expression) bool) {
	if expr == nil {
		return
	}
	if !fn(expr) {
		return
	}

	switch e := expr.(type) {
	case *BinaryExpr:
		if e != nil {
			Walk(e.Left, fn)
			Walk(e.Right, fn)
		}
	case *UnaryExpr:
		if e != nil {
			Walk(e.Operand, fn)
		}
	case *ParenExpr:
		if e != nil {
			Walk(e.Expr, fn)
		}
	case *TupleExpr:
		if e != nil {
			for _, elem := range e.Elements {
				Walk(elem, fn)
			}
		}
	}
}

// Accept dispatches to the appropriate visitor method.
func Accept(expr Expression, v Visitor) interface{} {
	switch e := expr.(type) {
	case *BinaryExpr:
		return v.VisitBinaryExpr(e)
	case *UnaryExpr:
		return v.VisitUnaryExpr(e)
	case *ParenExpr:
		return v.VisitParenExpr(e)
	case *FieldExpr:
		return v.VisitFieldExpr(e)
	case *MacroRef:
		return v.VisitMacroRef(e)
	case *ListRef:
		return v.VisitListRef(e)
	case *StringLiteral:
		return v.VisitStringLiteral(e)
	case *NumberLiteral:
		return v.VisitNumberLiteral(e)
	case *BoolLiteral:
		return v.VisitBoolLiteral(e)
	case *TupleExpr:
		return v.VisitTupleExpr(e)
	case *ErrorExpr:
		return v.VisitErrorExpr(e)
	default:
		return nil
	}
}
