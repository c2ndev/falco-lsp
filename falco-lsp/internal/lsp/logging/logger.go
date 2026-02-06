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

package logging

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

// Logger is the package-level logger for the LSP server.
var Logger *slog.Logger

// logFile holds the current log file so it can be closed on re-init.
var logFileHandle *os.File

// Level represents the logging level.
type Level int

// Logging level constants.
const (
	// LevelDebug enables debug-level logging.
	LevelDebug Level = iota
	// LevelInfo enables info-level logging.
	LevelInfo
	// LevelWarn enables warn-level logging.
	LevelWarn
	// LevelError enables error-level logging.
	LevelError
)

// Init initializes the package logger.
// If logFile is empty, logs go to stderr.
// If logFile is "-", logs go to stderr.
// Otherwise, logs go to the specified file.
func Init(logFile string, level Level) error {
	// Close the previous log file if one was open.
	if logFileHandle != nil {
		_ = logFileHandle.Close()
		logFileHandle = nil
	}

	var writer io.Writer = os.Stderr

	if logFile != "" && logFile != "-" {
		// Ensure log directory exists
		dir := filepath.Dir(logFile)
		// #nosec G301 - 0o750 is appropriate for log directories
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}

		// #nosec G304 - logFile is from trusted configuration, not user input
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		writer = f
		logFileHandle = f
	}

	var slogLevel slog.Level
	switch level {
	case LevelDebug:
		slogLevel = slog.LevelDebug
	case LevelInfo:
		slogLevel = slog.LevelInfo
	case LevelWarn:
		slogLevel = slog.LevelWarn
	case LevelError:
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: slogLevel,
	}

	Logger = slog.New(slog.NewJSONHandler(writer, opts))
	return nil
}

// init initializes the default logger.
func init() {
	// Default: log to stderr at Info level
	Logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}

// Debug logs a debug message.
func Debug(msg string, args ...any) {
	Logger.Debug(msg, args...)
}

// Info logs an info message.
func Info(msg string, args ...any) {
	Logger.Info(msg, args...)
}

// Warn logs a warning message.
func Warn(msg string, args ...any) {
	Logger.Warn(msg, args...)
}

// Error logs an error message.
func Error(msg string, args ...any) {
	Logger.Error(msg, args...)
}
