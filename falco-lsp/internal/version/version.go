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

package version

// ServerName is the canonical name of the language server.
const ServerName = "falco-language-server"

// DiagnosticSource is the source identifier used in LSP diagnostics.
// This appears in the IDE as the source of errors/warnings.
const DiagnosticSource = "falco"

// Build information set at compile time via ldflags.
var (
	// Version is the semantic version of the application.
	Version = "1.0.0"

	// BuildTime is the UTC timestamp when the binary was built.
	BuildTime = ""

	// Commit is the git commit hash of the build.
	Commit = ""
)

// Info returns a map of version information suitable for logging.
func Info() map[string]string {
	return map[string]string{
		"version":   Version,
		"buildTime": BuildTime,
		"commit":    Commit,
	}
}
