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

package config

import (
	"os"
	"strconv"
)

// Default configuration values.
const (
	// DefaultMaxContentLength is the maximum size of LSP messages (10MB).
	DefaultMaxContentLength = 10 * 1024 * 1024

	// DefaultMaxCompletionItems is the maximum number of completion items to return.
	DefaultMaxCompletionItems = 100

	// DefaultMaxDiagnostics is the maximum number of diagnostics per file.
	DefaultMaxDiagnostics = 1000

	// DefaultTabSize is the default indentation size.
	DefaultTabSize = 2

	// DefaultLogLevel is the default logging level.
	DefaultLogLevel = "info"
)

// List preview limits for different contexts.
// These are intentionally different: symbols need compact display, hover shows more detail.
const (
	// ListPreviewItemsSymbol is the max items to show in symbol outline/detail.
	ListPreviewItemsSymbol = 3

	// ListPreviewItemsHover is the max items to show in hover tooltip.
	ListPreviewItemsHover = 10

	// ListPreviewItemsCompletion is the max items to show in completion documentation.
	ListPreviewItemsCompletion = 10
)

// YAML key offsets - character positions after "- key: " patterns.
// These are used for calculating symbol positions in location creation.
const (
	// OffsetMacroName is the character offset for macro names after "- macro: ".
	OffsetMacroName = 9

	// OffsetListName is the character offset for list names after "- list: ".
	OffsetListName = 8

	// OffsetRuleName is the character offset for rule names after "- rule: ".
	OffsetRuleName = 8
)

// YAMLListItemPrefix is the prefix for YAML list items.
const YAMLListItemPrefix = "- "

// Config holds runtime configuration values.
type Config struct {
	// MaxContentLength is the maximum size of LSP messages.
	MaxContentLength int

	// MaxCompletionItems is the maximum number of completion items to return.
	MaxCompletionItems int

	// MaxDiagnostics is the maximum number of diagnostics per file.
	MaxDiagnostics int

	// TabSize is the default indentation size for formatting.
	TabSize int

	// LogLevel is the logging level (debug, info, warn, error).
	LogLevel string

	// LogFile is the path to the log file (empty or "-" for stderr).
	LogFile string
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		MaxContentLength:   DefaultMaxContentLength,
		MaxCompletionItems: DefaultMaxCompletionItems,
		MaxDiagnostics:     DefaultMaxDiagnostics,
		TabSize:            DefaultTabSize,
		LogLevel:           DefaultLogLevel,
		LogFile:            "",
	}
}

// FromEnvironment returns a configuration populated from environment variables.
//
// Environment variables:
//   - FALCO_LSP_MAX_CONTENT_LENGTH: Maximum LSP message size
//   - FALCO_LSP_MAX_COMPLETION_ITEMS: Maximum completion items
//   - FALCO_LSP_MAX_DIAGNOSTICS: Maximum diagnostics per file
//   - FALCO_LSP_TAB_SIZE: Default tab size
//   - FALCO_LSP_LOG_LEVEL: Logging level
//   - FALCO_LSP_LOG_FILE: Log file path
func FromEnvironment() *Config {
	cfg := DefaultConfig()

	if v := os.Getenv("FALCO_LSP_MAX_CONTENT_LENGTH"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.MaxContentLength = n
		}
	}

	if v := os.Getenv("FALCO_LSP_MAX_COMPLETION_ITEMS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.MaxCompletionItems = n
		}
	}

	if v := os.Getenv("FALCO_LSP_MAX_DIAGNOSTICS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.MaxDiagnostics = n
		}
	}

	if v := os.Getenv("FALCO_LSP_TAB_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.TabSize = n
		}
	}

	if v := os.Getenv("FALCO_LSP_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}

	if v := os.Getenv("FALCO_LSP_LOG_FILE"); v != "" {
		cfg.LogFile = v
	}

	return cfg
}
