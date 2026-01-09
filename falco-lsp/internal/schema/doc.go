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

// Package schema provides canonical definitions for Falco rule schemas.
//
// This package is the single source of truth for all Falco-specific constants,
// types, and definitions used throughout the LSP. It centralizes:
//
//   - Source types (syscall, k8s_audit, plugins)
//   - Priority levels (EMERGENCY, ALERT, CRITICAL, etc.)
//   - Property names (condition, output, priority, etc.)
//   - Block types (rule, macro, list, exception)
//   - Operators (comparison, logical, unary)
//   - Tags (MITRE, categories)
//   - Diagnostic codes (undefined-macro, wrong-source, etc.)
//   - Event types (syscalls)
//   - Identifier character classification
package schema
