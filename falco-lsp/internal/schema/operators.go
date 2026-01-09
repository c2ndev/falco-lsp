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

// OperatorInfo contains metadata about a Falco condition operator.
type OperatorInfo struct {
	Name        string
	Category    string // "comparison", "logical", "unary"
	Description string
}

// ComparisonOperators contains all comparison operators with descriptions.
// These operators are used in condition expressions to compare values.
var ComparisonOperators = []OperatorInfo{
	{"=", "comparison", "Equals"},
	{"==", "comparison", "Equals (alternative)"},
	{"!=", "comparison", "Not equals"},
	{"<", "comparison", "Less than"},
	{"<=", "comparison", "Less than or equal"},
	{">", "comparison", "Greater than"},
	{">=", "comparison", "Greater than or equal"},
	{"contains", "comparison", "String contains (case-sensitive)"},
	{"icontains", "comparison", "String contains (case-insensitive)"},
	{"bcontains", "comparison", "Buffer/binary contains"},
	{"startswith", "comparison", "String starts with (case-sensitive)"},
	{"istartswith", "comparison", "String starts with (case-insensitive)"},
	{"bstartswith", "comparison", "Buffer/binary starts with"},
	{"endswith", "comparison", "String ends with (case-sensitive)"},
	{"iendswith", "comparison", "String ends with (case-insensitive)"},
	{"bendswith", "comparison", "Buffer/binary ends with"},
	{"glob", "comparison", "Glob pattern match (case-sensitive)"},
	{"iglob", "comparison", "Glob pattern match (case-insensitive)"},
	{"regex", "comparison", "Regular expression match"},
	{"pmatch", "comparison", "Path match"},
	{"in", "comparison", "Value in list"},
	{"intersects", "comparison", "Lists intersect"},
	{"exists", "unary", "Field exists"},
}

// LogicalOperators contains all logical operators with descriptions.
var LogicalOperators = []OperatorInfo{
	{"and", "logical", "Logical AND operator"},
	{"or", "logical", "Logical OR operator"},
	{"not", "unary", "Logical NOT operator"},
}

// AllOperators returns all operators (comparison + logical).
func AllOperators() []OperatorInfo {
	result := make([]OperatorInfo, 0, len(ComparisonOperators)+len(LogicalOperators))
	result = append(result, ComparisonOperators...)
	result = append(result, LogicalOperators...)
	return result
}
