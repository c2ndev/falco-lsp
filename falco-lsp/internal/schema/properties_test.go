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

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPropertyNameString(t *testing.T) {
	tests := []struct {
		prop     PropertyName
		expected string
	}{
		{PropRule, "rule"},
		{PropMacro, "macro"},
		{PropList, "list"},
		{PropCondition, "condition"},
		{PropOutput, "output"},
		{PropPriority, "priority"},
		{PropSource, "source"},
		{PropDesc, "desc"},
		{PropTags, "tags"},
		{PropEnabled, "enabled"},
		{PropAppend, "append"},
		{PropItems, "items"},
		{PropExceptions, "exceptions"},
		{PropOverride, "override"},
		{PropRequiredEngineVersion, "required_engine_version"},
		{PropRequiredPluginVersions, "required_plugin_versions"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.prop.String())
		})
	}
}

func TestRulePropertiesContainsRequiredProperties(t *testing.T) {
	requiredProps := make(map[PropertyName]bool)
	for _, prop := range RuleProperties {
		if prop.Required {
			requiredProps[prop.Name] = true
		}
	}

	// A rule must have at minimum: desc, condition, output, priority
	assert.True(t, requiredProps[PropDesc], "desc should be required for rules")
	assert.True(t, requiredProps[PropCondition], "condition should be required for rules")
	assert.True(t, requiredProps[PropOutput], "output should be required for rules")
	assert.True(t, requiredProps[PropPriority], "priority should be required for rules")
}

func TestMacroPropertiesContainsRequiredProperties(t *testing.T) {
	requiredProps := make(map[PropertyName]bool)
	for _, prop := range MacroProperties {
		if prop.Required {
			requiredProps[prop.Name] = true
		}
	}

	// A macro must have: condition
	assert.True(t, requiredProps[PropCondition], "condition should be required for macros")
}

func TestListPropertiesContainsRequiredProperties(t *testing.T) {
	requiredProps := make(map[PropertyName]bool)
	for _, prop := range ListProperties {
		if prop.Required {
			requiredProps[prop.Name] = true
		}
	}

	// A list must have: items
	assert.True(t, requiredProps[PropItems], "items should be required for lists")
}

func TestExceptionPropertiesExist(t *testing.T) {
	assert.NotEmpty(t, ExceptionProperties)

	propNames := make(map[PropertyName]bool)
	for _, prop := range ExceptionProperties {
		propNames[prop.Name] = true
	}

	// Exception block should have these properties
	assert.True(t, propNames[PropExceptionName], "name should be in exception properties")
	assert.True(t, propNames[PropExceptionFields], "fields should be in exception properties")
}

func TestOverrideablePropertiesExist(t *testing.T) {
	assert.NotEmpty(t, OverrideableProperties)

	// Check that common overrideable properties exist
	propNames := make(map[PropertyName]bool)
	for _, prop := range OverrideableProperties {
		propNames[prop.Name] = true
	}

	// These properties can typically be overridden
	assert.True(t, propNames[PropCondition], "condition should be overrideable")
	assert.True(t, propNames[PropOutput], "output should be overrideable")
}
