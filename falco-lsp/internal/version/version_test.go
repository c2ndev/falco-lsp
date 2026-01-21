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

package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionDefaults(t *testing.T) {
	// Version should have a default value, BuildTime and Commit are set by ldflags
	assert.NotEmpty(t, Version, "Version should not be empty by default")
	// BuildTime and Commit are optional - they're set via -ldflags during build
	// So we just verify they're strings (can be empty)
	_ = BuildTime
	_ = Commit
}

func TestInfo(t *testing.T) {
	info := Info()

	require.NotNil(t, info, "Info() returned nil")

	assert.Contains(t, info, "version", "Info() should contain 'version' key")
	assert.Contains(t, info, "buildTime", "Info() should contain 'buildTime' key")
	assert.Contains(t, info, "commit", "Info() should contain 'commit' key")

	// Verify values match the variables
	assert.Equal(t, Version, info["version"], "Info()['version'] mismatch")
	assert.Equal(t, BuildTime, info["buildTime"], "Info()['buildTime'] mismatch")
	assert.Equal(t, Commit, info["commit"], "Info()['commit'] mismatch")
}
