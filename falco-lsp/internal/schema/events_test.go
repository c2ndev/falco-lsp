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

func TestAllEventTypesNotEmpty(t *testing.T) {
	allEvents := AllEventTypes()
	assert.NotEmpty(t, allEvents, "AllEventTypes should return events")
}

func TestProcessEventTypesContainsExpected(t *testing.T) {
	events := make(map[string]bool)
	for _, evt := range ProcessEventTypes {
		events[evt.Name] = true
	}

	// Common process-related syscalls
	assert.True(t, events["execve"], "Should contain execve")
	assert.True(t, events["fork"], "Should contain fork")
	assert.True(t, events["clone"], "Should contain clone")
}

func TestFileEventTypesContainsExpected(t *testing.T) {
	events := make(map[string]bool)
	for _, evt := range FileEventTypes {
		events[evt.Name] = true
	}

	// Common file-related syscalls
	assert.True(t, events["open"], "Should contain open")
	assert.True(t, events["read"], "Should contain read")
	assert.True(t, events["write"], "Should contain write")
}

func TestNetworkEventTypesContainsExpected(t *testing.T) {
	events := make(map[string]bool)
	for _, evt := range NetworkEventTypes {
		events[evt.Name] = true
	}

	// Common network-related syscalls
	assert.True(t, events["connect"], "Should contain connect")
	assert.True(t, events["accept"], "Should contain accept")
	assert.True(t, events["bind"], "Should contain bind")
}

func TestCommonBinariesNotEmpty(t *testing.T) {
	assert.NotEmpty(t, CommonBinaries, "CommonBinaries should contain binaries")

	// Check some common binaries
	binaries := make(map[string]bool)
	for _, bin := range CommonBinaries {
		binaries[bin] = true
	}

	assert.True(t, binaries["bash"], "Should contain bash")
	assert.True(t, binaries["sh"], "Should contain sh")
}

func TestAllEventTypesContainsAllCategories(t *testing.T) {
	allEvents := AllEventTypes()

	// Total should be sum of all event categories
	expectedTotal := len(ProcessEventTypes) + len(FileEventTypes) + len(NetworkEventTypes) +
		len(PermissionEventTypes) + len(SignalEventTypes)
	assert.Equal(t, expectedTotal, len(allEvents))
}

func TestEventTypesHaveCategories(t *testing.T) {
	allEvents := AllEventTypes()

	for _, evt := range allEvents {
		assert.NotEmpty(t, evt.Name, "Event should have a name")
		assert.NotEmpty(t, evt.Category, "Event %s should have a category", evt.Name)
	}
}
