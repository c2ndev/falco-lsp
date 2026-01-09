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

// TagInfo contains metadata about a rule tag.
type TagInfo struct {
	Name        string
	Description string
	Category    string // "category", "mitre-technique", "mitre-tactic"
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

// MITRETechniqueTags contains MITRE ATT&CK technique tags.
var MITRETechniqueTags = []TagInfo{
	{"T1059", "MITRE: Command and Scripting Interpreter", "mitre-technique"},
	{"T1068", "MITRE: Exploitation for Privilege Escalation", "mitre-technique"},
	{"T1078", "MITRE: Valid Accounts", "mitre-technique"},
	{"T1105", "MITRE: Ingress Tool Transfer", "mitre-technique"},
	{"T1190", "MITRE: Exploit Public-Facing Application", "mitre-technique"},
	{"T1210", "MITRE: Exploitation of Remote Services", "mitre-technique"},
	{"T1548", "MITRE: Abuse Elevation Control Mechanism", "mitre-technique"},
	{"T1611", "MITRE: Escape to Host", "mitre-technique"},
}

// MITRETacticTags contains MITRE ATT&CK tactic tags.
var MITRETacticTags = []TagInfo{
	{"mitre_execution", "MITRE Execution tactic", "mitre-tactic"},
	{"mitre_persistence", "MITRE Persistence tactic", "mitre-tactic"},
	{"mitre_privilege_escalation", "MITRE Privilege Escalation tactic", "mitre-tactic"},
	{"mitre_defense_evasion", "MITRE Defense Evasion tactic", "mitre-tactic"},
	{"mitre_credential_access", "MITRE Credential Access tactic", "mitre-tactic"},
	{"mitre_discovery", "MITRE Discovery tactic", "mitre-tactic"},
	{"mitre_lateral_movement", "MITRE Lateral Movement tactic", "mitre-tactic"},
	{"mitre_collection", "MITRE Collection tactic", "mitre-tactic"},
	{"mitre_exfiltration", "MITRE Exfiltration tactic", "mitre-tactic"},
	{"mitre_impact", "MITRE Impact tactic", "mitre-tactic"},
}

// AllTags returns all tags (categories + MITRE techniques + MITRE tactics).
func AllTags() []TagInfo {
	result := make([]TagInfo, 0, len(CategoryTags)+len(MITRETechniqueTags)+len(MITRETacticTags))
	result = append(result, CategoryTags...)
	result = append(result, MITRETechniqueTags...)
	result = append(result, MITRETacticTags...)
	return result
}
