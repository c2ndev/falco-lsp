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

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, DefaultMaxContentLength, cfg.MaxContentLength, "MaxContentLength")
	assert.Equal(t, DefaultMaxCompletionItems, cfg.MaxCompletionItems, "MaxCompletionItems")
	assert.Equal(t, DefaultMaxDiagnostics, cfg.MaxDiagnostics, "MaxDiagnostics")
	assert.Equal(t, DefaultTabSize, cfg.TabSize, "TabSize")
	assert.Equal(t, "info", cfg.LogLevel, "LogLevel")
}

func TestFromEnvironment(t *testing.T) {
	// Set environment variables using t.Setenv (auto-cleanup)
	t.Setenv("FALCO_LSP_MAX_CONTENT_LENGTH", "5000000")
	t.Setenv("FALCO_LSP_MAX_COMPLETION_ITEMS", "50")
	t.Setenv("FALCO_LSP_MAX_DIAGNOSTICS", "500")
	t.Setenv("FALCO_LSP_TAB_SIZE", "4")
	t.Setenv("FALCO_LSP_LOG_LEVEL", "debug")
	t.Setenv("FALCO_LSP_LOG_FILE", "/tmp/test.log")

	cfg := FromEnvironment()

	assert.Equal(t, 5000000, cfg.MaxContentLength, "MaxContentLength")
	assert.Equal(t, 50, cfg.MaxCompletionItems, "MaxCompletionItems")
	assert.Equal(t, 500, cfg.MaxDiagnostics, "MaxDiagnostics")
	assert.Equal(t, 4, cfg.TabSize, "TabSize")
	assert.Equal(t, "debug", cfg.LogLevel, "LogLevel")
	assert.Equal(t, "/tmp/test.log", cfg.LogFile, "LogFile")
}

func TestFromEnvironmentInvalidValues(t *testing.T) {
	// Set invalid values using t.Setenv (auto-cleanup)
	t.Setenv("FALCO_LSP_MAX_CONTENT_LENGTH", "invalid")
	t.Setenv("FALCO_LSP_TAB_SIZE", "-1")

	cfg := FromEnvironment()

	// Should use defaults for invalid values
	assert.Equal(t, DefaultMaxContentLength, cfg.MaxContentLength, "MaxContentLength should be default for invalid value")
	assert.Equal(t, DefaultTabSize, cfg.TabSize, "TabSize should be default for negative value")
}
