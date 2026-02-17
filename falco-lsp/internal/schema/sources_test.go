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

package schema

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSourceTypeString(t *testing.T) {
	tests := []struct {
		source   SourceType
		expected string
	}{
		{SourceSyscall, "syscall"},
		{SourceK8sAudit, "k8s_audit"},
		{SourceAWSCloudtrail, "aws_cloudtrail"},
		{SourceOkta, "okta"},
		{SourceGitHub, "github"},
		{SourceGCPAuditLog, "gcp_auditlog"},
		{SourceAzurePlatformLogs, "azure_platformlogs"},
		{SourceCloudtrail, "cloudtrail"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.source.String())
		})
	}
}

func TestDefaultSource(t *testing.T) {
	assert.Equal(t, SourceSyscall, DefaultSource)
	assert.Equal(t, "syscall", DefaultSource.String())
}

func TestAllSourcesContainsExpectedSources(t *testing.T) {
	sources := make(map[SourceType]bool)
	for _, s := range AllSources {
		sources[s.Type] = true
	}

	assert.True(t, sources[SourceSyscall], "AllSources should contain syscall")
	assert.True(t, sources[SourceK8sAudit], "AllSources should contain k8s_audit")
	assert.True(t, sources[SourceAWSCloudtrail], "AllSources should contain aws_cloudtrail")
}

func TestIsValidSource(t *testing.T) {
	tests := []struct {
		source   string
		expected bool
	}{
		{"syscall", true},
		{"k8s_audit", true},
		{"aws_cloudtrail", true},
		{"okta", true},
		{"github", true},
		{"gcp_auditlog", true},
		{"azure_platformlogs", true},
		{"invalid_source", false},
		{"", false},
		{"SYSCALL", false}, // Case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsValidSource(tt.source))
		})
	}
}

func TestGetFieldPrefixes(t *testing.T) {
	// Test syscall prefixes
	syscallPrefixes := GetFieldPrefixes(SourceSyscall)
	assert.NotEmpty(t, syscallPrefixes)
	assert.Contains(t, syscallPrefixes, "evt.")
	assert.Contains(t, syscallPrefixes, "proc.")

	// Test k8s_audit prefixes
	k8sPrefixes := GetFieldPrefixes(SourceK8sAudit)
	assert.NotEmpty(t, k8sPrefixes)
	assert.Contains(t, k8sPrefixes, "ka.")

	// Test unknown source
	unknownPrefixes := GetFieldPrefixes("unknown")
	assert.Nil(t, unknownPrefixes)
}

func TestGetFieldPrefixesForString(t *testing.T) {
	prefixes := GetFieldPrefixesForString("syscall")
	assert.NotEmpty(t, prefixes)
	assert.Contains(t, prefixes, "evt.")

	unknownPrefixes := GetFieldPrefixesForString("unknown")
	assert.Nil(t, unknownPrefixes)
}

func TestSourcePrefixMapCompleteness(t *testing.T) {
	// Every source in AllSources should have an entry in SourcePrefixMap
	// (except possibly aliases like cloudtrail)
	for _, s := range AllSources {
		prefixes := GetFieldPrefixes(s.Type)
		assert.NotNil(t, prefixes, "Source %s should have prefixes", s.Type)
	}
}
