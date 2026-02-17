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

package main

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestIsFalcoFile(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		// .falco.yaml / .falco.yml patterns
		{name: "falco yaml", path: "my-rules.falco.yaml", want: true},
		{name: "falco yml", path: "my-rules.falco.yml", want: true},
		{name: "nested falco yaml", path: "/etc/falco/rules.falco.yaml", want: true},

		// *_rules.yaml / *_rules.yml patterns (official Falco naming)
		{name: "falco_rules yaml", path: "falco_rules.yaml", want: true},
		{name: "k8s_audit_rules yaml", path: "k8s_audit_rules.yaml", want: true},
		{name: "falco-incubating_rules yaml", path: "falco-incubating_rules.yaml", want: true},
		{name: "custom_rules yml", path: "custom_rules.yml", want: true},
		{name: "nested rules yaml", path: "/etc/falco/falco_rules.yaml", want: true},

		// Generic .yaml / .yml (NOT matched — only specific Falco patterns)
		{name: "generic yaml", path: "rules.yaml", want: false},
		{name: "generic yml", path: "rules.yml", want: false},
		{name: "docker compose", path: "docker-compose.yaml", want: false},
		{name: "ci config", path: ".github/workflows/ci.yml", want: false},

		// Non-matching extensions
		{name: "json file", path: "rules.json", want: false},
		{name: "txt file", path: "notes.txt", want: false},
		{name: "no extension", path: "Makefile", want: false},
		{name: "toml file", path: "config.toml", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isFalcoFile(tt.path)
			if got != tt.want {
				t.Errorf("isFalcoFile(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestExpandPatternsDirectoryWalk(t *testing.T) {
	// Create a temp directory tree with mixed file types
	dir := t.TempDir()

	falcoFiles := []string{
		"falco_rules.yaml",
		"k8s_audit_rules.yaml",
		"custom_rules.yml",
		"my-rules.falco.yaml",
		"other.falco.yml",
	}
	nonFalcoFiles := []string{
		"docker-compose.yaml",
		"config.yml",
		"README.md",
		"values.yaml",
	}

	// Create all files
	for _, name := range append(falcoFiles, nonFalcoFiles...) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("# test"), 0o644); err != nil {
			t.Fatalf("failed to create %s: %v", name, err)
		}
	}

	// Also create a nested _rules file
	subdir := filepath.Join(dir, "subdir")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "nested_rules.yaml"), []byte("# test"), 0o644); err != nil {
		t.Fatalf("failed to create nested file: %v", err)
	}

	// Expand the temp directory
	got, err := expandPatterns([]string{dir})
	if err != nil {
		t.Fatalf("expandPatterns(%q) returned error: %v", dir, err)
	}

	// Build expected set (all falcoFiles + nested one)
	want := make(map[string]bool)
	for _, name := range falcoFiles {
		want[filepath.Join(dir, name)] = true
	}
	want[filepath.Join(subdir, "nested_rules.yaml")] = true

	// Build got set
	gotSet := make(map[string]bool, len(got))
	for _, f := range got {
		gotSet[f] = true
	}

	// Verify all expected files are present
	for path := range want {
		if !gotSet[path] {
			t.Errorf("expected file not found: %s", filepath.Base(path))
		}
	}

	// Verify no unexpected files are present
	for _, path := range got {
		if !want[path] {
			t.Errorf("unexpected file found: %s", filepath.Base(path))
		}
	}

	// Verify exact count
	if len(got) != len(want) {
		sort.Strings(got)
		t.Errorf("got %d files, want %d\ngot: %v", len(got), len(want), got)
	}
}
