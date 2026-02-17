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

// EventTypeInfo contains metadata about a syscall event type.
type EventTypeInfo struct {
	Name        string
	Category    string // "process", "file", "network", "permissions", "signal"
	Description string
}

// ProcessEventTypes contains process-related syscalls.
var ProcessEventTypes = []EventTypeInfo{
	{"execve", "process", "Execute program"},
	{"execveat", "process", "Execute program at path"},
	{"clone", "process", "Create child process"},
	{"fork", "process", "Create child process (legacy)"},
	{"vfork", "process", "Create child process (virtual memory)"},
}

// FileEventTypes contains file-related syscalls.
var FileEventTypes = []EventTypeInfo{
	{"open", "file", "Open file"},
	{"openat", "file", "Open file at directory"},
	{"openat2", "file", "Open file at directory (extended)"},
	{"close", "file", "Close file descriptor"},
	{"read", "file", "Read from file descriptor"},
	{"write", "file", "Write to file descriptor"},
	{"unlink", "file", "Delete file"},
	{"rename", "file", "Rename file"},
	{"symlink", "file", "Create symbolic link"},
	{"link", "file", "Create hard link"},
	{"mkdir", "file", "Create directory"},
	{"rmdir", "file", "Remove directory"},
	{"mount", "file", "Mount filesystem"},
	{"umount", "file", "Unmount filesystem"},
}

// NetworkEventTypes contains network-related syscalls.
var NetworkEventTypes = []EventTypeInfo{
	{"connect", "network", "Connect to remote host"},
	{"accept", "network", "Accept incoming connection"},
	{"bind", "network", "Bind to address"},
	{"listen", "network", "Listen for connections"},
	{"socket", "network", "Create socket"},
	{"sendto", "network", "Send data to address"},
	{"recvfrom", "network", "Receive data from address"},
}

// PermissionEventTypes contains permission-related syscalls.
var PermissionEventTypes = []EventTypeInfo{
	{"setuid", "permissions", "Set user ID"},
	{"setgid", "permissions", "Set group ID"},
	{"chmod", "permissions", "Change file permissions"},
	{"chown", "permissions", "Change file ownership"},
}

// SignalEventTypes contains signal-related syscalls.
var SignalEventTypes = []EventTypeInfo{
	{"kill", "signal", "Send signal to process"},
	{"ptrace", "signal", "Process trace (debugging)"},
}

// AllEventTypes returns all event types.
func AllEventTypes() []EventTypeInfo {
	result := make([]EventTypeInfo, 0,
		len(ProcessEventTypes)+len(FileEventTypes)+
			len(NetworkEventTypes)+len(PermissionEventTypes)+len(SignalEventTypes))
	result = append(result, ProcessEventTypes...)
	result = append(result, FileEventTypes...)
	result = append(result, NetworkEventTypes...)
	result = append(result, PermissionEventTypes...)
	result = append(result, SignalEventTypes...)
	return result
}

// CommonBinaries contains commonly referenced binary names for list completions.
var CommonBinaries = []string{
	// Shells
	"bash", "sh", "zsh", "fish", "ksh",
	// Container tools
	"docker", "kubectl", "crictl", "runc",
	// Network tools
	"nc", "ncat", "netcat", "socat",
	// Scripting/download tools
	"curl", "wget", "python", "perl", "ruby",
}
