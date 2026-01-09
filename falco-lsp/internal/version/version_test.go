// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Alessandro Cannarella

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
