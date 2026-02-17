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

// SourceType represents a Falco event source type.
// Source types define where events originate from (syscalls, audit logs, plugins).
type SourceType string

// Falco event source type constants.
// These are the valid values for the "source" field in Falco rules.
const (
	// SourceSyscall represents system call events (default source).
	SourceSyscall SourceType = "syscall"
	// SourceK8sAudit represents Kubernetes audit log events.
	SourceK8sAudit SourceType = "k8s_audit"
	// SourceAWSCloudtrail represents AWS CloudTrail events.
	SourceAWSCloudtrail SourceType = "aws_cloudtrail"
	// SourceOkta represents Okta identity events.
	SourceOkta SourceType = "okta"
	// SourceGitHub represents GitHub audit events.
	SourceGitHub SourceType = "github"
	// SourceGCPAuditLog represents GCP Audit Log events.
	SourceGCPAuditLog SourceType = "gcp_auditlog"
	// SourceAzurePlatformLogs represents Azure Platform Logs events.
	SourceAzurePlatformLogs SourceType = "azure_platformlogs"
	// SourceCloudtrail represents CloudTrail events (legacy/alias).
	SourceCloudtrail SourceType = "cloudtrail"
)

// String returns the string representation of the source type.
func (s SourceType) String() string {
	return string(s)
}

// SourceInfo contains metadata about a source type.
type SourceInfo struct {
	Type        SourceType
	Description string
}

// DefaultSource is the default source type for Falco rules.
const DefaultSource = SourceSyscall

// AllSources returns all known source types with their descriptions.
// This is the canonical list used for completion, validation, and documentation.
var AllSources = []SourceInfo{
	{SourceSyscall, "System call events (default)"},
	{SourceK8sAudit, "Kubernetes audit log events"},
	{SourceAWSCloudtrail, "AWS CloudTrail events"},
	{SourceOkta, "Okta identity events"},
	{SourceGitHub, "GitHub audit events"},
	{SourceGCPAuditLog, "GCP Audit Log events"},
	{SourceAzurePlatformLogs, "Azure Platform Logs events"},
}

// sourceSet is a fast lookup set for valid source types.
var sourceSet = func() map[SourceType]struct{} {
	m := make(map[SourceType]struct{}, len(AllSources))
	for _, s := range AllSources {
		m[s.Type] = struct{}{}
	}
	return m
}()

// IsValidSource checks if the given string is a valid source type.
func IsValidSource(s string) bool {
	_, ok := sourceSet[SourceType(s)]
	return ok
}

// SourcePrefixMap maps source types to their valid field prefixes.
// This is used for data-driven field validation to determine which
// fields are valid for each source type.
var SourcePrefixMap = map[SourceType][]string{
	SourceSyscall: {
		"evt.", "proc.", "thread.", "user.", "group.",
		"container.", "fd.", "fs.", "k8s.", "k8smeta.",
		"syscall.", "span.", "mesos.", "marathon.",
	},
	SourceK8sAudit: {
		"ka.", "jevt.", "k8s.",
	},
	SourceAWSCloudtrail: {
		"ct.", "aws.",
	},
	SourceGitHub: {
		"github.",
	},
	SourceOkta: {
		"okta.",
	},
	SourceGCPAuditLog: {
		"gcp.",
	},
	SourceAzurePlatformLogs: {
		"azure.",
	},
	SourceCloudtrail: {
		"ct.",
	},
}

// GetFieldPrefixes returns the valid field prefixes for a source type.
// Returns nil if the source type is unknown.
func GetFieldPrefixes(source SourceType) []string {
	return SourcePrefixMap[source]
}

// GetFieldPrefixesForString returns the valid field prefixes for a source type string.
// Returns nil if the source type is unknown.
func GetFieldPrefixesForString(source string) []string {
	return SourcePrefixMap[SourceType(source)]
}
