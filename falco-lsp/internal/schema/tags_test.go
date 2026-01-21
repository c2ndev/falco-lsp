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

func TestAllTagsNotEmpty(t *testing.T) {
	allTags := AllTags()
	assert.NotEmpty(t, allTags, "AllTags should return tags")
}

func TestCategoryTagsContainsExpected(t *testing.T) {
	categories := make(map[string]bool)
	for _, tag := range CategoryTags {
		categories[tag.Name] = true
	}

	// Common Falco rule categories
	assert.True(t, categories["container"], "Should contain container category")
	assert.True(t, categories["network"], "Should contain network category")
	assert.True(t, categories["process"], "Should contain process category")
	assert.True(t, categories["filesystem"], "Should contain filesystem category")
}

func TestMITRETacticTagsExist(t *testing.T) {
	assert.NotEmpty(t, MITRETacticTags, "Should have MITER tactic tags")

	// Check some common MITER tactics
	tactics := make(map[string]bool)
	for _, tag := range MITRETacticTags {
		tactics[tag.Name] = true
	}

	assert.True(t, tactics["miter_execution"], "Should contain miter_execution tactic")
	assert.True(t, tactics["miter_persistence"], "Should contain miter_persistence tactic")
	assert.True(t, tactics["miter_privilege_escalation"], "Should contain miter_privilege_escalation tactic")
}

func TestMITRETechniqueTagsExist(t *testing.T) {
	assert.NotEmpty(t, MITRETechniqueTags, "Should have MITER technique tags")

	// Check format of technique tags
	for _, tag := range MITRETechniqueTags {
		assert.NotEmpty(t, tag.Name)
		assert.NotEmpty(t, tag.Description)
	}
}

func TestAllTagsContainsAllCategories(t *testing.T) {
	allTags := AllTags()

	// Total should be sum of all tag categories
	expectedTotal := len(CategoryTags) + len(MITRETacticTags) + len(MITRETechniqueTags)
	assert.Equal(t, expectedTotal, len(allTags))
}
