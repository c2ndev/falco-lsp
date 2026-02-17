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

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPriorityString(t *testing.T) {
	tests := []struct {
		priority Priority
		expected string
	}{
		{PriorityEmergency, "EMERGENCY"},
		{PriorityAlert, "ALERT"},
		{PriorityCritical, "CRITICAL"},
		{PriorityError, "ERROR"},
		{PriorityWarning, "WARNING"},
		{PriorityNotice, "NOTICE"},
		{PriorityInformational, "INFORMATIONAL"},
		{PriorityDebug, "DEBUG"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.priority.String())
		})
	}
}

func TestDefaultPriority(t *testing.T) {
	assert.Equal(t, PriorityWarning, DefaultPriority)
	assert.Equal(t, "WARNING", DefaultPriority.String())
}

func TestAllPrioritiesOrdering(t *testing.T) {
	// Verify AllPriorities is ordered by severity (highest to lowest)
	assert.Equal(t, 8, len(AllPriorities), "Should have 8 priority levels")

	// Check that severity numbers are increasing (0 = highest severity)
	for i := 0; i < len(AllPriorities)-1; i++ {
		assert.Less(t, AllPriorities[i].Severity, AllPriorities[i+1].Severity,
			"Priority %s should have lower severity number than %s",
			AllPriorities[i].Level, AllPriorities[i+1].Level)
	}
}

func TestAllPrioritiesContainsExpectedLevels(t *testing.T) {
	priorities := make(map[Priority]bool)
	for _, p := range AllPriorities {
		priorities[p.Level] = true
	}

	assert.True(t, priorities[PriorityEmergency])
	assert.True(t, priorities[PriorityAlert])
	assert.True(t, priorities[PriorityCritical])
	assert.True(t, priorities[PriorityError])
	assert.True(t, priorities[PriorityWarning])
	assert.True(t, priorities[PriorityNotice])
	assert.True(t, priorities[PriorityInformational])
	assert.True(t, priorities[PriorityDebug])
}

func TestIsValidPriority(t *testing.T) {
	tests := []struct {
		priority string
		expected bool
	}{
		{"EMERGENCY", true},
		{"ALERT", true},
		{"CRITICAL", true},
		{"ERROR", true},
		{"WARNING", true},
		{"NOTICE", true},
		{"INFORMATIONAL", true},
		{"DEBUG", true},
		{"INVALID", false},
		{"", false},
		{"warning", false}, // Case sensitive
		{"Info", false},
	}

	for _, tt := range tests {
		t.Run(tt.priority, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsValidPriority(tt.priority))
		})
	}
}
