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

package router

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falco-lsp/internal/lsp/protocol"
)

func TestRouter_RegisterAndDispatch(t *testing.T) {
	r := New()

	// Register a request handler
	called := false
	r.RegisterHandler(protocol.MethodInitialize, func(msg *protocol.Message) *protocol.Message {
		called = true
		return &protocol.Message{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Result:  "ok",
		}
	})

	msg := &protocol.Message{
		JSONRPC: "2.0",
		ID:      1,
		Method:  protocol.MethodInitialize,
	}

	response := r.Dispatch(msg)

	assert.True(t, called, "handler should have been called")
	require.NotNil(t, response, "expected response")
	assert.Equal(t, 1, response.ID, "expected ID 1")
}

func TestRouter_NotificationHandler(t *testing.T) {
	r := New()

	called := false
	r.RegisterNotification(protocol.MethodInitialized, func(_ *protocol.Message) {
		called = true
	})

	msg := &protocol.Message{
		JSONRPC: "2.0",
		Method:  protocol.MethodInitialized,
	}

	response := r.Dispatch(msg)

	assert.True(t, called, "notification handler should have been called")
	assert.Nil(t, response, "notification should not return a response")
}

func TestRouter_UnknownMethod(t *testing.T) {
	r := New()

	tests := []struct {
		name           string
		msg            *protocol.Message
		expectResponse bool
		expectError    bool
	}{
		{
			name: "unknown request returns error",
			msg: &protocol.Message{
				JSONRPC: "2.0",
				ID:      1,
				Method:  "unknown/method",
			},
			expectResponse: true,
			expectError:    true,
		},
		{
			name: "unknown notification is ignored",
			msg: &protocol.Message{
				JSONRPC: "2.0",
				Method:  "unknown/notification",
			},
			expectResponse: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := r.Dispatch(tt.msg)

			if tt.expectResponse {
				assert.NotNil(t, response, "expected response")
			} else {
				assert.Nil(t, response, "expected no response")
			}
			if tt.expectError && response != nil {
				assert.NotNil(t, response.Error, "expected error in response")
			}
		})
	}
}

func TestRouter_HasHandler(t *testing.T) {
	r := New()

	assert.False(t, r.HasHandler(protocol.MethodInitialize), "should not have handler before registration")

	r.RegisterHandler(protocol.MethodInitialize, func(_ *protocol.Message) *protocol.Message {
		return nil
	})

	assert.True(t, r.HasHandler(protocol.MethodInitialize), "should have handler after registration")

	r.RegisterNotification(protocol.MethodInitialized, func(_ *protocol.Message) {})

	assert.True(t, r.HasHandler(protocol.MethodInitialized), "should have notification handler after registration")
}
