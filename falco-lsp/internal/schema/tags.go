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

package schema

// TagInfo contains metadata about a rule tag.
type TagInfo struct {
	Name        string
	Description string
	Category    string // "category", "miter-technique", "miter-tactic"
}

// CategoryTags contains common categorization tags.
var CategoryTags = []TagInfo{
	{"container", "Container-related rule", "category"},
	{"host", "Host-level rule", "category"},
	{"network", "Network activity", "category"},
	{"filesystem", "File system activity", "category"},
	{"process", "Process activity", "category"},
	{"security", "Security-related", "category"},
	{"compliance", "Compliance requirement", "category"},
}

// MITRETechniqueTags contains MITER ATT&CK technique tags.
var MITRETechniqueTags = []TagInfo{
	{"T1059", "MITER: Command and Scripting Interpreter", "miter-technique"},
	{"T1068", "MITER: Exploitation for Privilege Escalation", "miter-technique"},
	{"T1078", "MITER: Valid Accounts", "miter-technique"},
	{"T1105", "MITER: Ingress Tool Transfer", "miter-technique"},
	{"T1190", "MITER: Exploit Public-Facing Application", "miter-technique"},
	{"T1210", "MITER: Exploitation of Remote Services", "miter-technique"},
	{"T1548", "MITER: Abuse Elevation Control Mechanism", "miter-technique"},
	{"T1611", "MITER: Escape to Host", "miter-technique"},
}

// MITRETacticTags contains MITER ATT&CK tactic tags.
var MITRETacticTags = []TagInfo{
	{"miter_execution", "MITER Execution tactic", "miter-tactic"},
	{"miter_persistence", "MITER Persistence tactic", "miter-tactic"},
	{"miter_privilege_escalation", "MITER Privilege Escalation tactic", "miter-tactic"},
	{"miter_defense_evasion", "MITER Defense Evasion tactic", "miter-tactic"},
	{"miter_credential_access", "MITER Credential Access tactic", "miter-tactic"},
	{"miter_discovery", "MITER Discovery tactic", "miter-tactic"},
	{"miter_lateral_movement", "MITER Lateral Movement tactic", "miter-tactic"},
	{"miter_collection", "MITER Collection tactic", "miter-tactic"},
	{"miter_exfiltration", "MITER Exfiltration tactic", "miter-tactic"},
	{"miter_impact", "MITER Impact tactic", "miter-tactic"},
}

// AllTags returns all tags (categories + MITER techniques + MITER tactics).
func AllTags() []TagInfo {
	result := make([]TagInfo, 0, len(CategoryTags)+len(MITRETechniqueTags)+len(MITRETacticTags))
	result = append(result, CategoryTags...)
	result = append(result, MITRETechniqueTags...)
	result = append(result, MITRETacticTags...)
	return result
}
