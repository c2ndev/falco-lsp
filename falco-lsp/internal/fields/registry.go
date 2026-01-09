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

package fields

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/c2ndev/falco-lsp/internal/schema"
)

//go:embed data/syscall.json
var syscallData []byte

//go:embed data/k8saudit.json
var k8sauditData []byte

//go:embed data/plugins.json
var pluginsData []byte

// Field represents a Falco field definition.
type Field struct {
	Name        string
	Type        string
	Category    string
	Description string
	IsDynamic   bool
	Source      string // Source plugin/component this field belongs to (e.g., "syscall", "k8s_audit")
}

// Registry provides field lookup functionality.
type Registry struct {
	fields   map[string]*Field
	bySource map[string][]*Field
}

// SourcePrefixMap provides backward compatibility for code that directly accesses
// source prefixes. New code should use schema.SourcePrefixMap directly.
//
// Deprecated: Use schema.GetFieldPrefixesForString instead.
var SourcePrefixMap = convertSourcePrefixMap()

// convertSourcePrefixMap converts schema.SourcePrefixMap to map[string][]string.
func convertSourcePrefixMap() map[string][]string {
	result := make(map[string][]string)
	for source, prefixes := range schema.SourcePrefixMap {
		result[string(source)] = prefixes
	}
	return result
}

// NewRegistry creates a new field registry.
// Returns an error if the embedded field data cannot be parsed.
func NewRegistry() (*Registry, error) {
	r := &Registry{
		fields:   make(map[string]*Field),
		bySource: make(map[string][]*Field),
	}

	syscallSource := schema.SourceSyscall.String()
	k8sAuditSource := schema.SourceK8sAudit.String()

	// Load syscall fields
	var syscallFields []Field
	if err := json.Unmarshal(syscallData, &syscallFields); err != nil {
		return nil, fmt.Errorf("failed to load syscall fields: %w", err)
	}
	for i := range syscallFields {
		f := &syscallFields[i]
		f.Source = syscallSource
		r.fields[f.Name] = f
		r.bySource[syscallSource] = append(r.bySource[syscallSource], f)
	}

	// Load k8s audit fields
	var k8sFields []Field
	if err := json.Unmarshal(k8sauditData, &k8sFields); err != nil {
		return nil, fmt.Errorf("failed to load k8s audit fields: %w", err)
	}
	for i := range k8sFields {
		f := &k8sFields[i]
		f.Source = k8sAuditSource
		r.fields[f.Name] = f
		r.bySource[k8sAuditSource] = append(r.bySource[k8sAuditSource], f)
	}

	// Load plugin fields
	var pluginFields map[string][]Field
	if err := json.Unmarshal(pluginsData, &pluginFields); err != nil {
		return nil, fmt.Errorf("failed to load plugin fields: %w", err)
	}
	for source, fields := range pluginFields {
		for i := range fields {
			f := &fields[i]
			f.Source = source
			r.fields[f.Name] = f
			r.bySource[source] = append(r.bySource[source], f)
		}
	}

	return r, nil
}

// MustNewRegistry creates a new field registry and panics on error.
// Use this only for package initialization where error handling is not possible.
func MustNewRegistry() *Registry {
	r, err := NewRegistry()
	if err != nil {
		panic(err)
	}
	return r
}

// GetField returns a field by name.
func (r *Registry) GetField(name string) *Field {
	baseName := name
	if idx := strings.Index(name, "["); idx != -1 {
		baseName = name[:idx]
	}

	if f, ok := r.fields[baseName]; ok {
		return f
	}

	// Handle evt.arg.* pattern (dynamic argument access)
	if strings.HasPrefix(baseName, "evt.arg.") {
		return r.fields["evt.arg"]
	}

	// Handle thread.cap_* pattern
	if strings.HasPrefix(baseName, "thread.cap_") {
		if f, ok := r.fields["thread.cap_permitted"]; ok {
			return f
		}
	}

	return nil
}

// GetFieldsForSource returns all fields for a source.
func (r *Registry) GetFieldsForSource(source string) []*Field {
	return r.bySource[source]
}

// FieldExists checks if a field exists.
func (r *Registry) FieldExists(name string) bool {
	return r.GetField(name) != nil
}

// GetFieldsByCategory returns all fields in a category.
func (r *Registry) GetFieldsByCategory(category string) []*Field {
	var result []*Field
	for _, f := range r.fields {
		if f.Category == category {
			result = append(result, f)
		}
	}
	return result
}

// IsFieldAvailableForSource checks if a field is available for a given source.
func (r *Registry) IsFieldAvailableForSource(fieldName, source string) bool {
	// Get the field first
	field := r.GetField(fieldName)
	if field == nil {
		return false
	}

	// Check if the field is in the source's field list
	sourceFields := r.bySource[source]
	for _, f := range sourceFields {
		if f.Name == field.Name {
			return true
		}
	}

	return false
}

// DefaultRegistry is the default field registry.
// It is initialized at package load time using MustNewRegistry.
var DefaultRegistry = MustNewRegistry()

// GetField returns a field by name from the default registry.
func GetField(name string) *Field {
	return DefaultRegistry.GetField(name)
}

// GetFieldsByCategory returns all fields in a category from the default registry.
func GetFieldsByCategory(category string) []*Field {
	return DefaultRegistry.GetFieldsByCategory(category)
}

// GetAllFields returns all fields from the default registry.
func GetAllFields() []*Field {
	return DefaultRegistry.GetAllFields()
}

// GetAllFields returns all fields in the registry.
func (r *Registry) GetAllFields() []*Field {
	result := make([]*Field, 0, len(r.fields))
	for _, f := range r.fields {
		result = append(result, f)
	}
	return result
}
