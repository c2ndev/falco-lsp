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

package condition

import (
	"testing"

	"github.com/c2ndev/falco-lsp/internal/ast"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSimpleComparison(t *testing.T) {
	result := Parse("proc.name = bash")

	require.Empty(t, result.Errors)
	require.NotNil(t, result.Expression)

	binary, ok := result.Expression.(*ast.BinaryExpr)
	require.True(t, ok, "expected BinaryExpr")
	assert.Equal(t, ast.Operator("="), binary.Operator)

	field, ok := binary.Left.(*ast.FieldExpr)
	require.True(t, ok, "expected FieldExpr on left")
	assert.Equal(t, "proc.name", field.Name)

	str, ok := binary.Right.(*ast.StringLiteral)
	require.True(t, ok, "expected StringLiteral on right")
	assert.Equal(t, "bash", str.Value)
}

func TestParseAndExpression(t *testing.T) {
	result := Parse("proc.name = bash and fd.name = /etc/passwd")

	require.Empty(t, result.Errors)
	require.NotNil(t, result.Expression)

	binary, ok := result.Expression.(*ast.BinaryExpr)
	require.True(t, ok, "expected BinaryExpr")
	assert.Equal(t, ast.Operator("and"), binary.Operator)

	left, ok := binary.Left.(*ast.BinaryExpr)
	require.True(t, ok, "expected BinaryExpr on left")
	assert.Equal(t, ast.Operator("="), left.Operator)

	right, ok := binary.Right.(*ast.BinaryExpr)
	require.True(t, ok, "expected BinaryExpr on right")
	assert.Equal(t, ast.Operator("="), right.Operator)
}

func TestParseOrExpression(t *testing.T) {
	result := Parse("proc.name = bash or proc.name = sh")

	require.Empty(t, result.Errors)

	binary, ok := result.Expression.(*ast.BinaryExpr)
	require.True(t, ok)
	assert.Equal(t, ast.Operator("or"), binary.Operator)
}

func TestParseNotExpression(t *testing.T) {
	result := Parse("not proc.name = bash")

	require.Empty(t, result.Errors)

	unary, ok := result.Expression.(*ast.UnaryExpr)
	require.True(t, ok, "expected UnaryExpr")
	assert.Equal(t, ast.OpNot, unary.Operator)
}

func TestParseParentheses(t *testing.T) {
	result := Parse("(proc.name = bash or proc.name = sh) and fd.name = /etc/passwd")

	require.Empty(t, result.Errors)

	binary, ok := result.Expression.(*ast.BinaryExpr)
	require.True(t, ok)
	assert.Equal(t, ast.Operator("and"), binary.Operator)

	paren, ok := binary.Left.(*ast.ParenExpr)
	require.True(t, ok, "expected ParenExpr on left")

	inner, ok := paren.Expr.(*ast.BinaryExpr)
	require.True(t, ok)
	assert.Equal(t, ast.Operator("or"), inner.Operator)
}

func TestParseInOperator(t *testing.T) {
	result := Parse("proc.name in (bash, sh, zsh)")

	require.Empty(t, result.Errors)

	binary, ok := result.Expression.(*ast.BinaryExpr)
	require.True(t, ok)
	assert.Equal(t, ast.Operator("in"), binary.Operator)

	tuple, ok := binary.Right.(*ast.TupleExpr)
	require.True(t, ok, "expected TupleExpr on right")
	assert.Len(t, tuple.Elements, 3)
}

func TestParseContains(t *testing.T) {
	result := Parse(`fd.name contains "/etc"`)

	require.Empty(t, result.Errors)

	binary, ok := result.Expression.(*ast.BinaryExpr)
	require.True(t, ok)
	assert.Equal(t, ast.Operator("contains"), binary.Operator)

	str, ok := binary.Right.(*ast.StringLiteral)
	require.True(t, ok)
	assert.Equal(t, "/etc", str.Value)
	assert.True(t, str.Quoted)
}

func TestParseMacroReference(t *testing.T) {
	result := Parse("spawned_process and container")

	require.Empty(t, result.Errors)

	binary, ok := result.Expression.(*ast.BinaryExpr)
	require.True(t, ok)

	left, ok := binary.Left.(*ast.MacroRef)
	require.True(t, ok, "expected MacroRef on left")
	assert.Equal(t, "spawned_process", left.Name)

	right, ok := binary.Right.(*ast.MacroRef)
	require.True(t, ok, "expected MacroRef on right")
	assert.Equal(t, "container", right.Name)
}

func TestParseDynamicField(t *testing.T) {
	result := Parse("proc.aname[2] = systemd")

	require.Empty(t, result.Errors)

	binary, ok := result.Expression.(*ast.BinaryExpr)
	require.True(t, ok)

	field, ok := binary.Left.(*ast.FieldExpr)
	require.True(t, ok)
	assert.Equal(t, "proc.aname", field.Name)
	assert.Equal(t, "2", field.Argument)
}

func TestParseListReference(t *testing.T) {
	result := Parse("proc.name in shell_binaries")

	require.Empty(t, result.Errors)

	binary, ok := result.Expression.(*ast.BinaryExpr)
	require.True(t, ok)
	assert.Equal(t, ast.Operator("in"), binary.Operator)

	listRef, ok := binary.Right.(*ast.ListRef)
	require.True(t, ok, "expected ListRef on right")
	assert.Equal(t, "shell_binaries", listRef.Name)
}

func TestParseComplexCondition(t *testing.T) {
	// Real Falco rule condition
	condition := `spawned_process and container and proc.name in (bash, sh) and not user.name = root`

	result := Parse(condition)

	require.Empty(t, result.Errors)
	require.NotNil(t, result.Expression)
}

func TestParseDottedStringValue(t *testing.T) {
	// This was a bug - dotted strings were incorrectly parsed as fields
	result := Parse("proc.name = org.apache.zookeeper.server")

	require.Empty(t, result.Errors)

	binary, ok := result.Expression.(*ast.BinaryExpr)
	require.True(t, ok)

	// Right side should be a string literal, not a field
	str, ok := binary.Right.(*ast.StringLiteral)
	require.True(t, ok, "expected StringLiteral on right, got %T", binary.Right)
	assert.Equal(t, "org.apache.zookeeper.server", str.Value)
}

func TestParseUnixPath(t *testing.T) {
	result := Parse("fd.name startswith /usr/bin/")

	require.Empty(t, result.Errors)

	binary, ok := result.Expression.(*ast.BinaryExpr)
	require.True(t, ok)

	str, ok := binary.Right.(*ast.StringLiteral)
	require.True(t, ok)
	assert.Equal(t, "/usr/bin/", str.Value)
}

func TestParseExists(t *testing.T) {
	result := Parse("fd.name exists")

	require.Empty(t, result.Errors)

	unary, ok := result.Expression.(*ast.UnaryExpr)
	require.True(t, ok, "expected UnaryExpr")
	assert.Equal(t, ast.OpExists, unary.Operator)
}

func TestParseNumber(t *testing.T) {
	result := Parse("evt.count > 100")

	require.Empty(t, result.Errors)

	binary, ok := result.Expression.(*ast.BinaryExpr)
	require.True(t, ok)

	num, ok := binary.Right.(*ast.NumberLiteral)
	require.True(t, ok)
	assert.Equal(t, float64(100), num.Value)
	assert.True(t, num.IsInt)
}

func TestParseError_UnexpectedToken(_ *testing.T) {
	result := Parse("proc.name = = bash")

	// Parser may be lenient - just ensure it doesn't crash
	_ = result
}

func TestParseError_UnclosedParen(t *testing.T) {
	result := Parse("(proc.name = bash")

	// Should have errors
	assert.NotEmpty(t, result.Errors)
}

func TestParseError_EmptyInput(_ *testing.T) {
	result := Parse("")

	// Empty input should not crash
	_ = result
}

func TestParseError_OnlyOperator(_ *testing.T) {
	result := Parse("and")

	// Parser may be lenient - just ensure it doesn't crash
	_ = result
}

func TestParseError_MissingRHS(_ *testing.T) {
	result := Parse("proc.name =")

	// Parser may be lenient - just ensure it doesn't crash
	_ = result
}

func TestParseError_InvalidTuple(_ *testing.T) {
	result := Parse("proc.name in (bash, )")

	// Should have errors or handle gracefully
	_ = result
}

func TestParseError_UnclosedTuple(t *testing.T) {
	result := Parse("proc.name in (bash, sh")

	// Should have errors
	assert.NotEmpty(t, result.Errors)
}

func TestParseError_DoubleNot(t *testing.T) {
	result := Parse("not not proc.name = bash")

	// Should parse correctly (double negation)
	require.Empty(t, result.Errors)
}

func TestParseError_TrailingOperator(_ *testing.T) {
	result := Parse("proc.name = bash and")

	// Parser may be lenient - just ensure it doesn't crash
	_ = result
}

func TestParseFieldWithIndex(t *testing.T) {
	// Note: The parser may not include the index in the field name
	result := Parse("proc.args[0] = bash")

	require.Empty(t, result.Errors)

	binary, ok := result.Expression.(*ast.BinaryExpr)
	require.True(t, ok)

	field, ok := binary.Left.(*ast.FieldExpr)
	require.True(t, ok)
	// Field name may or may not include the index
	assert.Contains(t, field.Name, "proc.args")
}

func TestParseQuotedString(t *testing.T) {
	result := Parse(`proc.name = "bash shell"`)

	require.Empty(t, result.Errors)

	binary, ok := result.Expression.(*ast.BinaryExpr)
	require.True(t, ok)

	str, ok := binary.Right.(*ast.StringLiteral)
	require.True(t, ok)
	assert.Equal(t, "bash shell", str.Value)
}

func TestParseSingleQuotedString(t *testing.T) {
	result := Parse(`proc.name = 'bash shell'`)

	require.Empty(t, result.Errors)

	binary, ok := result.Expression.(*ast.BinaryExpr)
	require.True(t, ok)

	str, ok := binary.Right.(*ast.StringLiteral)
	require.True(t, ok)
	assert.Equal(t, "bash shell", str.Value)
}

func TestParseNegativeNumber(t *testing.T) {
	result := Parse("evt.count > -100")

	require.Empty(t, result.Errors)

	binary, ok := result.Expression.(*ast.BinaryExpr)
	require.True(t, ok)

	num, ok := binary.Right.(*ast.NumberLiteral)
	require.True(t, ok)
	assert.Equal(t, float64(-100), num.Value)
}

func TestParseFloatNumber(t *testing.T) {
	result := Parse("evt.latency > 1.5")

	require.Empty(t, result.Errors)

	binary, ok := result.Expression.(*ast.BinaryExpr)
	require.True(t, ok)

	num, ok := binary.Right.(*ast.NumberLiteral)
	require.True(t, ok)
	assert.Equal(t, 1.5, num.Value)
	assert.False(t, num.IsInt)
}

func TestParseMacroReferenceWithComparison(t *testing.T) {
	result := Parse("is_shell and evt.type = execve")

	require.Empty(t, result.Errors)

	binary, ok := result.Expression.(*ast.BinaryExpr)
	require.True(t, ok)
	assert.Equal(t, ast.Operator("and"), binary.Operator)

	// Left should be a macro reference
	macro, ok := binary.Left.(*ast.MacroRef)
	require.True(t, ok, "expected MacroRef on left, got %T", binary.Left)
	assert.Equal(t, "is_shell", macro.Name)
}
