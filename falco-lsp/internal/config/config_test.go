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
	"os"
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
	// Set environment variables
	os.Setenv("FALCO_LSP_MAX_CONTENT_LENGTH", "5000000")
	os.Setenv("FALCO_LSP_MAX_COMPLETION_ITEMS", "50")
	os.Setenv("FALCO_LSP_MAX_DIAGNOSTICS", "500")
	os.Setenv("FALCO_LSP_TAB_SIZE", "4")
	os.Setenv("FALCO_LSP_LOG_LEVEL", "debug")
	os.Setenv("FALCO_LSP_LOG_FILE", "/tmp/test.log")
	defer func() {
		os.Unsetenv("FALCO_LSP_MAX_CONTENT_LENGTH")
		os.Unsetenv("FALCO_LSP_MAX_COMPLETION_ITEMS")
		os.Unsetenv("FALCO_LSP_MAX_DIAGNOSTICS")
		os.Unsetenv("FALCO_LSP_TAB_SIZE")
		os.Unsetenv("FALCO_LSP_LOG_LEVEL")
		os.Unsetenv("FALCO_LSP_LOG_FILE")
	}()

	cfg := FromEnvironment()

	assert.Equal(t, 5000000, cfg.MaxContentLength, "MaxContentLength")
	assert.Equal(t, 50, cfg.MaxCompletionItems, "MaxCompletionItems")
	assert.Equal(t, 500, cfg.MaxDiagnostics, "MaxDiagnostics")
	assert.Equal(t, 4, cfg.TabSize, "TabSize")
	assert.Equal(t, "debug", cfg.LogLevel, "LogLevel")
	assert.Equal(t, "/tmp/test.log", cfg.LogFile, "LogFile")
}

func TestFromEnvironmentInvalidValues(t *testing.T) {
	// Set invalid values
	os.Setenv("FALCO_LSP_MAX_CONTENT_LENGTH", "invalid")
	os.Setenv("FALCO_LSP_TAB_SIZE", "-1")
	defer func() {
		os.Unsetenv("FALCO_LSP_MAX_CONTENT_LENGTH")
		os.Unsetenv("FALCO_LSP_TAB_SIZE")
	}()

	cfg := FromEnvironment()

	// Should use defaults for invalid values
	assert.Equal(t, DefaultMaxContentLength, cfg.MaxContentLength, "MaxContentLength should be default for invalid value")
	assert.Equal(t, DefaultTabSize, cfg.TabSize, "TabSize should be default for negative value")
}
