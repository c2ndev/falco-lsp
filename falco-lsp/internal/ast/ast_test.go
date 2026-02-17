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

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsComparisonOperator(t *testing.T) {
	tests := []struct {
		name     string
		operator string
		expected bool
	}{
		// Equality operators
		{"single equals", "=", true},
		{"double equals", "==", true},
		{"not equals", "!=", true},

		// Relational operators
		{"greater than", ">", true},
		{"greater than or equal", ">=", true},
		{"less than", "<", true},
		{"less than or equal", "<=", true},

		// Membership operators
		{"in operator", "in", true},
		{"intersects operator", "intersects", true},

		// String matching (case-sensitive)
		{"contains", "contains", true},
		{"startswith", "startswith", true},
		{"endswith", "endswith", true},

		// String matching (case-insensitive)
		{"icontains", "icontains", true},
		{"istartswith", "istartswith", true},
		{"iendswith", "iendswith", true},

		// String matching (buffer/binary)
		{"bcontains", "bcontains", true},
		{"bstartswith", "bstartswith", true},
		{"bendswith", "bendswith", true},

		// Pattern matching
		{"glob", "glob", true},
		{"iglob", "iglob", true},
		{"regex", "regex", true},
		{"pmatch", "pmatch", true},

		// Case-insensitive tests
		{"uppercase IN", "IN", true},
		{"uppercase CONTAINS", "CONTAINS", true},
		{"mixed case Contains", "Contains", true},
		{"uppercase ISTARTSWITH", "ISTARTSWITH", true},
		{"uppercase BENDSWITH", "BENDSWITH", true},

		// Logical operators (should be false)
		{"and is not comparison", "and", false},
		{"or is not comparison", "or", false},
		{"not is not comparison", "not", false},
		{"AND uppercase is not comparison", "AND", false},

		// Unary operators (should be false)
		{"exists is not comparison", "exists", false},
		{"EXISTS uppercase is not comparison", "EXISTS", false},

		// Invalid operators
		{"random string", "random", false},
		{"empty string", "", false},
		{"field name", "proc.name", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsComparisonOperator(tt.operator)
			assert.Equal(t, tt.expected, result,
				"IsComparisonOperator(%q) = %v, want %v", tt.operator, result, tt.expected)
		})
	}
}

func TestOperatorConstants(t *testing.T) {
	// Verify all operator constants are valid comparison operators
	comparisonOps := []Operator{
		OpEq, OpEqEq, OpNeq,
		OpGt, OpGte, OpLt, OpLte,
		OpIn, OpIntersects,
		OpContains, OpIContains, OpBContains,
		OpStartsWith, OpIStartsWith, OpBStartsWith,
		OpEndsWith, OpIEndsWith, OpBEndsWith,
		OpGlob, OpIGlob, OpRegex, OpPMatch,
	}

	for _, op := range comparisonOps {
		t.Run(string(op), func(t *testing.T) {
			assert.True(t, IsComparisonOperator(string(op)),
				"Operator constant %q should be recognized as comparison operator", op)
		})
	}

	// Verify logical operators are NOT comparison operators
	logicalOps := []Operator{OpAnd, OpOr, OpNot}
	for _, op := range logicalOps {
		t.Run(string(op), func(t *testing.T) {
			assert.False(t, IsComparisonOperator(string(op)),
				"Logical operator %q should NOT be recognized as comparison operator", op)
		})
	}
}

func TestIsComparisonOperatorConsistency(t *testing.T) {
	// Test that the function is consistent with case variations
	operators := []string{
		"contains", "icontains", "bcontains",
		"startswith", "istartswith", "bstartswith",
		"endswith", "iendswith", "bendswith",
		"glob", "iglob", "regex", "pmatch",
		"in", "intersects",
	}

	for _, op := range operators {
		t.Run(op, func(t *testing.T) {
			// All case variations should return the same result
			lower := IsComparisonOperator(op)
			upper := IsComparisonOperator(string([]byte(op))) // Keep original

			assert.True(t, lower, "lowercase %q should be comparison operator", op)
			assert.True(t, upper, "original case %q should be comparison operator", op)
		})
	}
}

func TestOperatorIsComparison(t *testing.T) {
	tests := []struct {
		name     string
		operator Operator
		expected bool
	}{
		// Comparison operators
		{"=", OpEq, true},
		{"==", OpEqEq, true},
		{"!=", OpNeq, true},
		{">", OpGt, true},
		{">=", OpGte, true},
		{"<", OpLt, true},
		{"<=", OpLte, true},
		{"in", OpIn, true},
		{"intersects", OpIntersects, true},
		{"contains", OpContains, true},
		{"istartswith", OpIStartsWith, true},
		{"bendswith", OpBEndsWith, true},

		// Logical operators (should be false)
		{"and", OpAnd, false},
		{"or", OpOr, false},
		{"not", OpNot, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.operator.IsComparison()
			assert.Equal(t, tt.expected, result,
				"Operator(%q).IsComparison() = %v, want %v", tt.operator, result, tt.expected)
		})
	}
}

func TestOperatorIsBinaryLogical(t *testing.T) {
	tests := []struct {
		name     string
		operator Operator
		expected bool
	}{
		{"and", OpAnd, true},
		{"or", OpOr, true},
		{"not is unary", OpNot, false},
		{"exists is unary", OpExists, false},
		{"= is comparison", OpEq, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.operator.IsBinaryLogical()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestOperatorIsUnary(t *testing.T) {
	tests := []struct {
		name     string
		operator Operator
		expected bool
	}{
		{"not", OpNot, true},
		{"exists", OpExists, true},
		{"and is binary", OpAnd, false},
		{"= is comparison", OpEq, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.operator.IsUnary()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsOperator(t *testing.T) {
	tests := []struct {
		name     string
		op       string
		expected bool
	}{
		// Comparison operators
		{"=", "=", true},
		{"contains", "contains", true},
		{"CONTAINS", "CONTAINS", true},

		// Binary logical operators
		{"and", "and", true},
		{"or", "or", true},
		{"AND", "AND", true},

		// Unary operators
		{"not", "not", true},
		{"exists", "exists", true},
		{"NOT", "NOT", true},

		// Not operators
		{"proc.name", "proc.name", false},
		{"bash", "bash", false},
		{"", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsOperator(tt.op)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsLogicalOperatorString(t *testing.T) {
	tests := []struct {
		name     string
		op       string
		expected bool
	}{
		// Binary logical operators
		{"and", "and", true},
		{"or", "or", true},
		{"AND", "AND", true},
		{"Or", "Or", true},

		// Not is unary, not binary logical
		{"not", "not", false},

		// Comparison operators
		{"=", "=", false},
		{"contains", "contains", false},
		{"exists", "exists", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsLogicalOperator(tt.op)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsUnaryOperatorString(t *testing.T) {
	tests := []struct {
		name     string
		op       string
		expected bool
	}{
		// Unary operators
		{"not", "not", true},
		{"exists", "exists", true},
		{"NOT", "NOT", true},
		{"EXISTS", "EXISTS", true},

		// Binary logical operators
		{"and", "and", false},
		{"or", "or", false},

		// Comparison operators
		{"=", "=", false},
		{"contains", "contains", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsUnaryOperator(tt.op)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ---- New tests for AST node types and utilities ----

func TestOperatorString(t *testing.T) {
	tests := []struct {
		op       Operator
		expected string
	}{
		{OpAnd, "and"},
		{OpOr, "or"},
		{OpNot, "not"},
		{OpEq, "="},
		{OpContains, "contains"},
		{OpIStartsWith, "istartswith"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.op.String())
		})
	}
}

func TestNewOperator(t *testing.T) {
	tests := []struct {
		input    string
		expected Operator
	}{
		{"AND", OpAnd},
		{"and", OpAnd},
		{"And", OpAnd},
		{"CONTAINS", OpContains},
		{"Contains", OpContains},
		{"IStartsWith", OpIStartsWith},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NewOperator(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBinaryExprNode(t *testing.T) {
	expr := &BinaryExpr{
		Range: Range{
			Start: Position{Line: 1, Column: 0, Offset: 0},
			End:   Position{Line: 1, Column: 10, Offset: 10},
		},
		Operator: OpEq,
	}

	assert.Equal(t, "BinaryExpr", expr.nodeType())
	assert.Equal(t, 1, expr.Pos().Start.Line)
	assert.Equal(t, 10, expr.Pos().End.Column)

	// Ensure it satisfies Expression interface
	var _ Expression = expr
}

func TestUnaryExprNode(t *testing.T) {
	expr := &UnaryExpr{
		Range: Range{
			Start: Position{Line: 5, Column: 2, Offset: 50},
			End:   Position{Line: 5, Column: 12, Offset: 60},
		},
		Operator: OpNot,
	}

	assert.Equal(t, "UnaryExpr", expr.nodeType())
	assert.Equal(t, 5, expr.Pos().Start.Line)
}

func TestParenExprNode(t *testing.T) {
	expr := &ParenExpr{
		Range: Range{
			Start: Position{Line: 1, Column: 0, Offset: 0},
			End:   Position{Line: 1, Column: 20, Offset: 20},
		},
	}

	assert.Equal(t, "ParenExpr", expr.nodeType())
	assert.Equal(t, 0, expr.Pos().Start.Column)
}

func TestFieldExprNode(t *testing.T) {
	expr := &FieldExpr{
		Range: Range{
			Start: Position{Line: 1, Column: 0, Offset: 0},
			End:   Position{Line: 1, Column: 9, Offset: 9},
		},
		Name:     "proc.name",
		Argument: "",
	}

	assert.Equal(t, "FieldExpr", expr.nodeType())
	assert.Equal(t, "proc.name", expr.Name)
}

func TestMacroRefNode(t *testing.T) {
	expr := &MacroRef{
		Range: Range{
			Start: Position{Line: 3, Column: 4, Offset: 30},
			End:   Position{Line: 3, Column: 15, Offset: 41},
		},
		Name: "container",
	}

	assert.Equal(t, "MacroRef", expr.nodeType())
	assert.Equal(t, 3, expr.Pos().Start.Line)
}

func TestListRefNode(t *testing.T) {
	expr := &ListRef{
		Range: Range{
			Start: Position{Line: 1, Column: 0, Offset: 0},
			End:   Position{Line: 1, Column: 10, Offset: 10},
		},
		Name: "allowed_procs",
	}

	assert.Equal(t, "ListRef", expr.nodeType())
	assert.Equal(t, "allowed_procs", expr.Name)
}

func TestStringLiteralNode(t *testing.T) {
	expr := &StringLiteral{
		Range: Range{
			Start: Position{Line: 1, Column: 0, Offset: 0},
			End:   Position{Line: 1, Column: 5, Offset: 5},
		},
		Value:  "bash",
		Quoted: true,
	}

	assert.Equal(t, "StringLiteral", expr.nodeType())
	assert.True(t, expr.Quoted)
}

func TestNumberLiteralNode(t *testing.T) {
	expr := &NumberLiteral{
		Range: Range{
			Start: Position{Line: 1, Column: 0, Offset: 0},
			End:   Position{Line: 1, Column: 3, Offset: 3},
		},
		Value: 42.0,
		Raw:   "42",
		IsInt: true,
	}

	assert.Equal(t, "NumberLiteral", expr.nodeType())
	assert.True(t, expr.IsInt)
	assert.Equal(t, 42.0, expr.Value)
}

func TestBoolLiteralNode(t *testing.T) {
	expr := &BoolLiteral{
		Range: Range{
			Start: Position{Line: 1, Column: 0, Offset: 0},
			End:   Position{Line: 1, Column: 4, Offset: 4},
		},
		Value: true,
	}

	assert.Equal(t, "BoolLiteral", expr.nodeType())
	assert.True(t, expr.Value)
}

func TestTupleExprNode(t *testing.T) {
	expr := &TupleExpr{
		Range: Range{
			Start: Position{Line: 1, Column: 0, Offset: 0},
			End:   Position{Line: 1, Column: 20, Offset: 20},
		},
		Elements: []Expression{
			&StringLiteral{Value: "a"},
			&StringLiteral{Value: "b"},
		},
	}

	assert.Equal(t, "TupleExpr", expr.nodeType())
	assert.Len(t, expr.Elements, 2)
}

func TestErrorExprNode(t *testing.T) {
	expr := &ErrorExpr{
		Range: Range{
			Start: Position{Line: 1, Column: 0, Offset: 0},
			End:   Position{Line: 1, Column: 5, Offset: 5},
		},
		Message: "unexpected token",
	}

	assert.Equal(t, "ErrorExpr", expr.nodeType())
	assert.Equal(t, "unexpected token", expr.Message)
}

func TestWalk(t *testing.T) {
	// Build a simple tree: (not (a = b)) and (c contains d)
	left := &UnaryExpr{
		Operator: OpNot,
		Operand: &ParenExpr{
			Expr: &BinaryExpr{
				Left:     &FieldExpr{Name: "a"},
				Operator: OpEq,
				Right:    &StringLiteral{Value: "b"},
			},
		},
	}
	right := &BinaryExpr{
		Left:     &FieldExpr{Name: "c"},
		Operator: OpContains,
		Right:    &StringLiteral{Value: "d"},
	}
	root := &BinaryExpr{
		Left:     left,
		Operator: OpAnd,
		Right:    right,
	}

	// Collect all node types
	var visited []string
	Walk(root, func(e Expression) bool {
		visited = append(visited, e.nodeType())
		return true
	})

	// Check we visited all nodes
	assert.Contains(t, visited, "BinaryExpr")
	assert.Contains(t, visited, "UnaryExpr")
	assert.Contains(t, visited, "ParenExpr")
	assert.Contains(t, visited, "FieldExpr")
	assert.Contains(t, visited, "StringLiteral")
	// 3 BinaryExpr + 1 UnaryExpr + 1 ParenExpr + 2 FieldExpr + 2 StringLiteral = 9
	assert.Len(t, visited, 9)
}

func TestWalkStopsWhenFalse(t *testing.T) {
	root := &BinaryExpr{
		Left:     &FieldExpr{Name: "a"},
		Operator: OpAnd,
		Right:    &FieldExpr{Name: "b"},
	}

	var count int
	Walk(root, func(_ Expression) bool {
		count++
		return false // Stop immediately
	})

	assert.Equal(t, 1, count) // Only visited the root
}

func TestWalkNilExpr(t *testing.T) {
	// Should not panic
	Walk(nil, func(_ Expression) bool {
		t.Error("should not be called")
		return true
	})
}

func TestWalkTupleExpr(t *testing.T) {
	tuple := &TupleExpr{
		Elements: []Expression{
			&StringLiteral{Value: "a"},
			&StringLiteral{Value: "b"},
			&StringLiteral{Value: "c"},
		},
	}

	var values []string
	Walk(tuple, func(e Expression) bool {
		if s, ok := e.(*StringLiteral); ok {
			values = append(values, s.Value)
		}
		return true
	})

	assert.Equal(t, []string{"a", "b", "c"}, values)
}

// testVisitor for Accept function tests.
type testVisitor struct {
	visited []string
}

func (v *testVisitor) VisitBinaryExpr(_ *BinaryExpr) interface{} {
	v.visited = append(v.visited, "BinaryExpr")
	return nil
}

func (v *testVisitor) VisitUnaryExpr(_ *UnaryExpr) interface{} {
	v.visited = append(v.visited, "UnaryExpr")
	return nil
}

func (v *testVisitor) VisitParenExpr(_ *ParenExpr) interface{} {
	v.visited = append(v.visited, "ParenExpr")
	return nil
}

func (v *testVisitor) VisitFieldExpr(_ *FieldExpr) interface{} {
	v.visited = append(v.visited, "FieldExpr")
	return nil
}

func (v *testVisitor) VisitMacroRef(_ *MacroRef) interface{} {
	v.visited = append(v.visited, "MacroRef")
	return nil
}

func (v *testVisitor) VisitListRef(_ *ListRef) interface{} {
	v.visited = append(v.visited, "ListRef")
	return nil
}

func (v *testVisitor) VisitStringLiteral(_ *StringLiteral) interface{} {
	v.visited = append(v.visited, "StringLiteral")
	return nil
}

func (v *testVisitor) VisitNumberLiteral(_ *NumberLiteral) interface{} {
	v.visited = append(v.visited, "NumberLiteral")
	return nil
}

func (v *testVisitor) VisitBoolLiteral(_ *BoolLiteral) interface{} {
	v.visited = append(v.visited, "BoolLiteral")
	return nil
}

func (v *testVisitor) VisitTupleExpr(_ *TupleExpr) interface{} {
	v.visited = append(v.visited, "TupleExpr")
	return nil
}

func (v *testVisitor) VisitErrorExpr(_ *ErrorExpr) interface{} {
	v.visited = append(v.visited, "ErrorExpr")
	return nil
}

func TestAccept(t *testing.T) {
	tests := []struct {
		name     string
		expr     Expression
		expected string
	}{
		{"BinaryExpr", &BinaryExpr{}, "BinaryExpr"},
		{"UnaryExpr", &UnaryExpr{}, "UnaryExpr"},
		{"ParenExpr", &ParenExpr{}, "ParenExpr"},
		{"FieldExpr", &FieldExpr{}, "FieldExpr"},
		{"MacroRef", &MacroRef{}, "MacroRef"},
		{"ListRef", &ListRef{}, "ListRef"},
		{"StringLiteral", &StringLiteral{}, "StringLiteral"},
		{"NumberLiteral", &NumberLiteral{}, "NumberLiteral"},
		{"BoolLiteral", &BoolLiteral{}, "BoolLiteral"},
		{"TupleExpr", &TupleExpr{}, "TupleExpr"},
		{"ErrorExpr", &ErrorExpr{}, "ErrorExpr"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &testVisitor{}
			Accept(tt.expr, v)
			assert.Equal(t, []string{tt.expected}, v.visited)
		})
	}
}

func TestAcceptNil(t *testing.T) {
	v := &testVisitor{}
	result := Accept(nil, v)
	assert.Nil(t, result)
	assert.Empty(t, v.visited)
}
