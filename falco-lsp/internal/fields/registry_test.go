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

package fields

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRegistry(t *testing.T) {
	r, err := NewRegistry()
	require.NoError(t, err, "NewRegistry returned error")
	require.NotNil(t, r, "NewRegistry returned nil")
	require.NotNil(t, r.fields, "Registry fields map is nil")
	require.NotNil(t, r.bySource, "Registry bySource map is nil")
}

func TestGetField(t *testing.T) {
	r, err := NewRegistry()
	require.NoError(t, err, "NewRegistry returned error")

	tests := []struct {
		name     string
		field    string
		wantName string
		wantNil  bool
	}{
		{"basic field", "evt.num", "evt.num", false},
		{"container field", "container.id", "container.id", false},
		{"process field", "proc.name", "proc.name", false},
		{"non-existent field", "nonexistent.field", "", true},
		{"field with index", "evt.arg[0]", "evt.arg", false},
		{"dynamic evt.arg", "evt.arg.myarg", "evt.arg", false},
		{"thread capability", "thread.cap_effective", "thread.cap_effective", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			field := r.GetField(tt.field)
			if tt.wantNil {
				assert.Nil(t, field, "GetField(%q) should be nil", tt.field)
			} else {
				require.NotNil(t, field, "GetField(%q) should not be nil", tt.field)
				assert.Equal(t, tt.wantName, field.Name, "GetField(%q).Name", tt.field)
			}
		})
	}
}

func TestFieldExists(t *testing.T) {
	r, err := NewRegistry()
	require.NoError(t, err, "NewRegistry returned error")

	tests := []struct {
		field string
		want  bool
	}{
		{"evt.num", true},
		{"container.id", true},
		{"proc.name", true},
		{"nonexistent.field", false},
		{"evt.arg[0]", true},
		{"evt.arg.myarg", true},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			got := r.FieldExists(tt.field)
			assert.Equal(t, tt.want, got, "FieldExists(%q)", tt.field)
		})
	}
}

func TestGetFieldsForSource(t *testing.T) {
	r, err := NewRegistry()
	require.NoError(t, err, "NewRegistry returned error")

	tests := []struct {
		source   string
		wantNone bool
	}{
		{"syscall", false},
		{"k8s_audit", false},
		{"cloudtrail", false},
		{"nonexistent_source", true},
	}

	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			fields := r.GetFieldsForSource(tt.source)
			if tt.wantNone {
				assert.Empty(t, fields, "GetFieldsForSource(%q) should return 0 fields", tt.source)
			} else {
				assert.NotEmpty(t, fields, "GetFieldsForSource(%q) should return > 0 fields", tt.source)
			}
		})
	}
}

func TestIsFieldAvailableForSource(t *testing.T) {
	r, err := NewRegistry()
	require.NoError(t, err, "NewRegistry returned error")

	tests := []struct {
		name   string
		field  string
		source string
		want   bool
	}{
		{"syscall field in syscall", "evt.num", "syscall", true},
		{"syscall field in k8s_audit", "evt.num", "k8s_audit", false},
		{"k8s field in k8s_audit", "ka.verb", "k8s_audit", true},
		{"k8s field in syscall", "ka.verb", "syscall", false},
		{"non-existent field", "nonexistent.field", "syscall", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.IsFieldAvailableForSource(tt.field, tt.source)
			assert.Equal(t, tt.want, got, "IsFieldAvailableForSource(%q, %q)", tt.field, tt.source)
		})
	}
}

func TestDefaultRegistry(t *testing.T) {
	require.NotNil(t, DefaultRegistry, "DefaultRegistry is nil")

	// Test that default registry functions work
	field := GetField("evt.num")
	assert.NotNil(t, field, "GetField from default registry returned nil")
}

func TestPluginFieldsLoaded(t *testing.T) {
	r, err := NewRegistry()
	require.NoError(t, err, "NewRegistry returned error")

	// Test cloudtrail fields
	cloudtrailFields := r.GetFieldsForSource("cloudtrail")
	assert.NotEmpty(t, cloudtrailFields, "No cloudtrail fields loaded")

	// Test specific cloudtrail field
	ctField := r.GetField("ct.name")
	require.NotNil(t, ctField, "ct.name field not found")
	assert.Equal(t, "ct.name", ctField.Name, "Expected ct.name")

	// Test okta fields
	oktaFields := r.GetFieldsForSource("okta")
	assert.NotEmpty(t, oktaFields, "No okta fields loaded")

	// Test github fields
	githubFields := r.GetFieldsForSource("github")
	assert.NotEmpty(t, githubFields, "No github fields loaded")

	t.Logf("Loaded %d cloudtrail fields", len(cloudtrailFields))
	t.Logf("Loaded %d okta fields", len(oktaFields))
	t.Logf("Loaded %d github fields", len(githubFields))
}

func TestAllFieldsIncludePlugins(t *testing.T) {
	r, err := NewRegistry()
	require.NoError(t, err, "NewRegistry returned error")
	allFields := r.GetAllFields()

	// Count fields by source
	sources := make(map[string]int)
	for _, f := range allFields {
		// Find which source this field belongs to
		for source, fields := range r.bySource {
			for _, sf := range fields {
				if sf.Name == f.Name {
					sources[source]++
					break
				}
			}
		}
	}

	t.Logf("Fields by source:")
	for source, count := range sources {
		t.Logf("  %s: %d fields", source, count)
	}

	// Verify we have plugin fields
	assert.NotZero(t, sources["cloudtrail"], "No cloudtrail fields in GetAllFields()")
	assert.NotZero(t, sources["okta"], "No okta fields in GetAllFields()")
}
