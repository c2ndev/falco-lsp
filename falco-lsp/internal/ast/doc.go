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

// Package ast defines Abstract Syntax Tree types for Falco condition expressions.
//
// The AST represents parsed condition expressions as a tree of nodes including:
//   - Binary expressions (and, or, comparisons)
//   - Unary expressions (not, exists)
//   - Field references (proc.name, fd.name)
//   - Macro and list references
//   - Literals (strings, numbers, booleans)
//
// All AST nodes include position information for error reporting and
// navigation features like go-to-definition.
package ast
