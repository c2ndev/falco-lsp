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

// Package lsp implements a Language Server Protocol server for Falco rules.
//
// The server provides IDE features for Falco rule files including:
//   - Code completion for rules, macros, lists, and fields
//   - Go-to-definition for macro and list references
//   - Hover information for fields and symbols
//   - Diagnostics for semantic errors
//   - Document formatting
//   - Document symbols outline
//   - Find references
//
// The server communicates via JSON-RPC over stdin/stdout following the
// Language Server Protocol specification.
package lsp
