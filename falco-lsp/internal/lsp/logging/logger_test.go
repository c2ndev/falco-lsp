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

// Package logging provides logging utilities for the LSP server.
package logging

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInit(t *testing.T) {
	// Test with stderr (empty path)
	err := Init("", LevelDebug)
	require.NoError(t, err, "Init failed")
	require.NotNil(t, Logger, "Logger should not be nil after Init")
}

func TestInitWithFile(t *testing.T) {
	// Save and restore Logger so file handle is released before TempDir cleanup.
	oldLogger := Logger
	defer func() { Logger = oldLogger }()

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	err := Init(logFile, LevelInfo)
	require.NoError(t, err, "Init with file failed")
	require.NotNil(t, Logger, "Logger should not be nil")

	// Write a log message
	Info("test message")

	// Verify file was created
	_, err = os.Stat(logFile)
	assert.False(t, os.IsNotExist(err), "log file should exist")

	// Reset logger to stderr to release the file handle (required for Windows cleanup).
	_ = Init("", LevelInfo)
}

func TestInitWithDash(t *testing.T) {
	// Test with "-" (stderr)
	err := Init("-", LevelWarn)
	require.NoError(t, err, "Init with dash failed")
}

func TestLogLevelConstants(t *testing.T) {
	assert.Less(t, LevelDebug, LevelInfo, "Debug should be less than Info")
	assert.Less(t, LevelInfo, LevelWarn, "Info should be less than Warn")
	assert.Less(t, LevelWarn, LevelError, "Warn should be less than Error")
}

func TestDebug(t *testing.T) {
	// Save and restore Logger
	oldLogger := Logger
	defer func() { Logger = oldLogger }()

	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	Logger = slog.New(handler)

	Debug("test message", "key", "value")

	assert.Contains(t, buf.String(), "test message", "expected message in log output")
}

func TestInfo(t *testing.T) {
	oldLogger := Logger
	defer func() { Logger = oldLogger }()

	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	Logger = slog.New(handler)

	Info("info message", "count", 42)

	assert.Contains(t, buf.String(), "info message", "expected message in log output")
}

func TestWarn(t *testing.T) {
	oldLogger := Logger
	defer func() { Logger = oldLogger }()

	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	Logger = slog.New(handler)

	Warn("warning message", "detail", "something")

	assert.Contains(t, buf.String(), "warning message", "expected message in log output")
}

func TestError(t *testing.T) {
	oldLogger := Logger
	defer func() { Logger = oldLogger }()

	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError})
	Logger = slog.New(handler)

	Error("error message", "err", "something went wrong")

	assert.Contains(t, buf.String(), "error message", "expected message in log output")
}

func TestLogWithMultipleArgs(t *testing.T) {
	oldLogger := Logger
	defer func() { Logger = oldLogger }()

	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	Logger = slog.New(handler)

	Debug("complex message",
		"key1", "value1",
		"key2", 123,
		"key3", true,
	)

	assert.Contains(t, buf.String(), "key1", "expected key1 in output")
	assert.Contains(t, buf.String(), "value1", "expected value1 in output")
}
