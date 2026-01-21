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

// Snippet represents a code snippet for autocompletion.
type Snippet struct {
	Label       string
	InsertText  string
	Description string
	Detail      string
}

// AllSnippets contains all available Falco rule snippets.
var AllSnippets = []Snippet{
	{
		Label:       "rule",
		Detail:      "Falco Rule",
		Description: "Detection rule with condition, output, and priority",
		InsertText: `- rule: ${1:name}
  desc: ${2:description}
  condition: ${3:condition}
  output: "${4:output message}"
  priority: ${5|WARNING,CRITICAL,ERROR,ALERT,EMERGENCY,NOTICE,INFO,DEBUG|}
  source: ${6|syscall,k8s_audit,aws_cloudtrail,okta,github|}
  tags: [${7:tag}]$0`,
	},
	{
		Label:       "rule-exceptions",
		Detail:      "Rule with Exceptions",
		Description: "Detection rule with exception handling",
		InsertText: `- rule: ${1:Rule Name}
  desc: ${2:Description}
  condition: ${3:condition}
  output: "${4:Output message}"
  priority: ${5|WARNING,CRITICAL,ERROR,ALERT,EMERGENCY,NOTICE,INFO,DEBUG|}
  source: ${6|syscall,k8s_audit,aws_cloudtrail,okta,github|}
  exceptions:
    - name: ${7:exception_name}
      fields: [${8:field}]
      comps: [${9|=,!=,in,intersects|}]
      values:
        - [${10:value}]
  tags: [${11:tag}]$0`,
	},
	{
		Label:       "macro",
		Detail:      "Falco Macro",
		Description: "Reusable condition fragment",
		InsertText: `- macro: ${1:name}
  condition: ${2:condition}$0`,
	},
	{
		Label:       "list",
		Detail:      "Falco List",
		Description: "Named collection of values",
		InsertText: `- list: ${1:name}
  items: [${2:item1, item2}]$0`,
	},
	{
		Label:       "required_engine_version",
		Detail:      "Required Engine Version",
		Description: "Minimum Falco engine version required",
		InsertText:  `- required_engine_version: ${1:0.38.0}$0`,
	},
	{
		Label:       "required_plugin_versions",
		Detail:      "Required Plugin Versions",
		Description: "Plugin version requirements",
		InsertText: `- required_plugin_versions:
    - name: ${1:plugin_name}
      version: ${2:0.0.0}$0`,
	},
	{
		Label:       "append-rule",
		Detail:      "Append Rule",
		Description: "Extend an existing rule's condition",
		InsertText: `- rule: ${1:Existing Rule Name}
  append: true
  condition: and ${2:additional_condition}$0`,
	},
	{
		Label:       "append-macro",
		Detail:      "Append Macro",
		Description: "Extend an existing macro's condition",
		InsertText: `- macro: ${1:existing_macro}
  append: true
  condition: or ${2:additional_condition}$0`,
	},
	{
		Label:       "append-list",
		Detail:      "Append List",
		Description: "Add items to an existing list",
		InsertText: `- list: ${1:existing_list}
  append: true
  items: [${2:additional_items}]$0`,
	},
	{
		Label:       "override-rule",
		Detail:      "Override Rule",
		Description: "Override specific properties of an existing rule",
		InsertText: `- rule: ${1:Existing Rule Name}
  override:
    ${2|desc,condition,output,priority,enabled,tags,warn_evttypes,skip-if-unknown-filter|}: ${3|replace,append|}$0`,
	},
}
