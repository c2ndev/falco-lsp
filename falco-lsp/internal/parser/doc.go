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

// Package parser implements YAML parsing for Falco rule files.
//
// The parser reads YAML-formatted Falco rule files and produces a structured
// document containing rules, macros, and lists with full position information.
//
// Example usage:
//
//	result, err := parser.Parse(content, "rules.yaml")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, item := range result.Document.Items {
//	    switch rule := item.(type) {
//	    case parser.Rule:
//	        fmt.Printf("Rule: %s\n", rule.Name)
//	    }
//	}
package parser
