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

// Package analyzer implements semantic analysis for Falco rules.
//
// The analyzer performs symbol collection, validation of conditions,
// and generates diagnostics for Falco rule files. It validates:
//   - Macro and list references
//   - Field names against known Falco fields
//   - Duplicate symbol definitions
//
// Example usage:
//
//	a := analyzer.NewAnalyzer()
//	result := a.Analyze(doc, "file:///path/to/rules.yaml")
//	for _, diag := range result.Diagnostics {
//	    fmt.Printf("%s: %s\n", diag.Severity, diag.Message)
//	}
package analyzer
