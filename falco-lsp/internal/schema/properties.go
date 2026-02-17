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

// PropertyName represents a Falco rule property name.
type PropertyName string

// Rule property name constants.
// These are the valid property names for different Falco block types.
const (
	// Common properties.
	PropCondition PropertyName = "condition"
	PropAppend    PropertyName = "append"

	// Rule properties.
	PropRule            PropertyName = "rule"
	PropDesc            PropertyName = "desc"
	PropOutput          PropertyName = "output"
	PropPriority        PropertyName = "priority"
	PropSource          PropertyName = "source"
	PropTags            PropertyName = "tags"
	PropEnabled         PropertyName = "enabled"
	PropExceptions      PropertyName = "exceptions"
	PropOverride        PropertyName = "override"
	PropCapture         PropertyName = "capture"
	PropCaptureDuration PropertyName = "capture_duration"
	PropWarnEvttypes    PropertyName = "warn_evttypes" // #nosec G101 -- not a credential
	PropSkipIfUnknown   PropertyName = "skip-if-unknown-filter"

	// Macro properties.
	PropMacro PropertyName = "macro"

	// List properties.
	PropList  PropertyName = "list"
	PropItems PropertyName = "items"

	// Exception properties.
	PropExceptionName   PropertyName = "name"
	PropExceptionFields PropertyName = "fields"
	PropExceptionComps  PropertyName = "comps"
	PropExceptionValues PropertyName = "values"

	// Engine/plugin version properties.
	PropRequiredEngineVersion  PropertyName = "required_engine_version"
	PropRequiredPluginVersions PropertyName = "required_plugin_versions"
)

// String returns the string representation of the property name.
func (p PropertyName) String() string {
	return string(p)
}

// PropertyInfo contains metadata about a rule property.
type PropertyInfo struct {
	Name        PropertyName
	Description string
	Required    bool
	BlockTypes  []string // Which block types this property applies to
}

// RuleProperties returns all properties for rule blocks.
var RuleProperties = []PropertyInfo{
	{PropDesc, "Rule description", true, []string{"rule"}},
	{PropCondition, "Detection condition expression", true, []string{"rule"}},
	{PropOutput, "Alert output message", true, []string{"rule"}},
	{PropPriority, "Alert priority level", true, []string{"rule"}},
	{PropSource, "Event source (syscall, k8s_audit, etc.)", false, []string{"rule"}},
	{PropTags, "Rule tags for categorization", false, []string{"rule"}},
	{PropEnabled, "Enable or disable the rule", false, []string{"rule"}},
	{PropAppend, "Append to existing rule", false, []string{"rule"}},
	{PropExceptions, "Rule exceptions", false, []string{"rule"}},
	{PropOverride, "Override rule properties", false, []string{"rule"}},
	{PropCapture, "Enable packet capture for this rule", false, []string{"rule"}},
	{PropCaptureDuration, "Duration of packet capture in seconds", false, []string{"rule"}},
	{PropWarnEvttypes, "Warn about event type filters", false, []string{"rule"}},
	{PropSkipIfUnknown, "Skip if filter unknown", false, []string{"rule"}},
}

// MacroProperties returns all properties for macro blocks.
var MacroProperties = []PropertyInfo{
	{PropCondition, "Macro condition expression", true, []string{"macro"}},
	{PropAppend, "Append to existing macro", false, []string{"macro"}},
}

// ListProperties returns all properties for list blocks.
var ListProperties = []PropertyInfo{
	{PropItems, "List items", true, []string{"list"}},
	{PropAppend, "Append to existing list", false, []string{"list"}},
}

// ExceptionProperties returns all properties for exception blocks.
var ExceptionProperties = []PropertyInfo{
	{PropExceptionName, "Name of the exception", true, []string{"exception"}},
	{PropExceptionFields, "Fields to match for exception (array of field names)", false, []string{"exception"}},
	{PropExceptionComps, "Comparison operators for each field (array)", false, []string{"exception"}},
	{PropExceptionValues, "Values to match against (array of arrays)", false, []string{"exception"}},
}

// OverrideableProperties returns properties that can be overridden.
var OverrideableProperties = []PropertyInfo{
	{PropCondition, "Override rule condition", false, []string{"override"}},
	{PropOutput, "Override rule output", false, []string{"override"}},
	{PropPriority, "Override rule priority", false, []string{"override"}},
	{PropTags, "Override rule tags", false, []string{"override"}},
	{PropEnabled, "Override rule enabled state", false, []string{"override"}},
	{PropExceptions, "Override rule exceptions", false, []string{"override"}},
	{PropSource, "Override rule source", false, []string{"override"}},
}

// Plugin version property constants.
const (
	PropPluginName    PropertyName = "name"
	PropPluginVersion PropertyName = "version"
)

// PluginVersionProperties returns properties for plugin version blocks.
var PluginVersionProperties = []PropertyInfo{
	{PropPluginName, "Plugin name", true, []string{"plugin_version"}},
	{PropPluginVersion, "Plugin version", true, []string{"plugin_version"}},
}
