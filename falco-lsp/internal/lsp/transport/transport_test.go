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

package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/c2ndev/falco-lsp/internal/lsp/protocol"
)

func TestTransport_ReadMessage(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantErr     bool
		errContains string
		wantMethod  protocol.Method
	}{
		{
			name:       "valid message",
			input:      "Content-Length: 46\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}",
			wantErr:    false,
			wantMethod: protocol.MethodInitialize,
		},
		{
			name:        "missing content length",
			input:       "\r\n{\"jsonrpc\":\"2.0\"}",
			wantErr:     true,
			errContains: "missing Content-Length",
		},
		{
			name:        "invalid content length",
			input:       "Content-Length: abc\r\n\r\n{}",
			wantErr:     true,
			errContains: "invalid Content-Length",
		},
		{
			name:        "content length too large",
			input:       "Content-Length: 999999999999\r\n\r\n{}",
			wantErr:     true,
			errContains: "exceeds maximum",
		},
		{
			name:        "negative content length",
			input:       "Content-Length: -1\r\n\r\n{}",
			wantErr:     true,
			errContains: "exceeds maximum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.input)
			transport := New(reader, nil)

			msg, err := transport.ReadMessage()

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantMethod, msg.Method)
			}
		})
	}
}

func TestTransport_WriteMessage(t *testing.T) {
	var buf bytes.Buffer
	transport := New(nil, &buf)

	msg := &protocol.Message{
		JSONRPC: "2.0",
		ID:      1,
		Method:  protocol.MethodInitialize,
	}

	err := transport.WriteMessage(msg)
	require.NoError(t, err)

	output := buf.String()

	// Should have Content-Length header
	assert.True(t, strings.HasPrefix(output, "Content-Length:"), "output should start with Content-Length header")

	// Should have valid JSON body
	parts := strings.SplitN(output, "\r\n\r\n", 2)
	require.Len(t, parts, 2, "output should have header and body separated by CRLF CRLF")

	var parsed protocol.Message
	err = json.Unmarshal([]byte(parts[1]), &parsed)
	require.NoError(t, err, "body should be valid JSON")
	assert.Equal(t, protocol.MethodInitialize, parsed.Method)
}

func TestTransport_ConcurrentWrites(t *testing.T) {
	var buf bytes.Buffer
	transport := New(nil, &buf)

	// Concurrent writes should not panic or corrupt data
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			msg := &protocol.Message{
				JSONRPC: "2.0",
				ID:      id,
			}
			_ = transport.WriteMessage(msg)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// Output should contain multiple Content-Length headers
	output := buf.String()
	count := strings.Count(output, "Content-Length:")
	assert.Equal(t, 10, count, "expected 10 Content-Length headers")
}

func TestTransport_ReadMessageWithContext(t *testing.T) {
	t.Run("successful read", func(t *testing.T) {
		input := "Content-Length: 46\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}"
		reader := strings.NewReader(input)
		transport := New(reader, nil)

		ctx := context.Background()
		msg, err := transport.ReadMessageWithContext(ctx)

		require.NoError(t, err)
		assert.Equal(t, protocol.MethodInitialize, msg.Method)
	})

	t.Run("context canceled", func(t *testing.T) {
		// Create a reader that blocks forever
		reader, _ := newBlockingReader()
		transport := New(reader, nil)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		_, err := transport.ReadMessageWithContext(ctx)

		require.Error(t, err, "expected context cancellation error")
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Logf("got error: %v (expected context.DeadlineExceeded)", err)
		}
	})
}

// blockingReader is a reader that blocks forever.
type blockingReader struct {
	ch chan struct{}
}

func newBlockingReader() (reader *blockingReader, cleanup func()) {
	r := &blockingReader{ch: make(chan struct{})}
	return r, func() { close(r.ch) }
}

func (r *blockingReader) Read(_ []byte) (n int, err error) {
	<-r.ch // Block forever until closed
	return 0, nil
}

func TestTransport_DefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, maxContentLength, cfg.MaxContentLength, "MaxContentLength")
	assert.Equal(t, DefaultReadTimeout, cfg.ReadTimeout, "ReadTimeout")
	assert.Equal(t, DefaultWriteTimeout, cfg.WriteTimeout, "WriteTimeout")
}

func TestTransport_NewWithConfig(t *testing.T) {
	cfg := Config{
		MaxContentLength: 1024,
		ReadTimeout:      5 * time.Second,
		WriteTimeout:     3 * time.Second,
	}

	reader := strings.NewReader("")
	transport := NewWithConfig(reader, nil, cfg)

	assert.Equal(t, 1024, transport.config.MaxContentLength)
}

func TestTransport_NewWithConfig_Defaults(t *testing.T) {
	// Zero values should use defaults
	cfg := Config{}

	reader := strings.NewReader("")
	transport := NewWithConfig(reader, nil, cfg)

	assert.Equal(t, maxContentLength, transport.config.MaxContentLength, "MaxContentLength should use default")
	assert.Equal(t, DefaultReadTimeout, transport.config.ReadTimeout, "ReadTimeout should use default")
}
