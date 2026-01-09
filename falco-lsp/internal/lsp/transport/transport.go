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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/c2ndev/falco-lsp/internal/lsp/protocol"
)

// maxContentLength is the maximum allowed message size (10MB).
// This prevents OOM attacks from malicious Content-Length headers.
const maxContentLength = 10 * 1024 * 1024

// DefaultReadTimeout is the default timeout for reading a message.
const DefaultReadTimeout = 30 * time.Second

// DefaultWriteTimeout is the default timeout for writing a message.
const DefaultWriteTimeout = 10 * time.Second

// Config holds transport configuration.
type Config struct {
	// MaxContentLength is the maximum allowed message size.
	MaxContentLength int

	// ReadTimeout is the timeout for reading a complete message.
	ReadTimeout time.Duration

	// WriteTimeout is the timeout for writing a message.
	WriteTimeout time.Duration
}

// DefaultConfig returns the default transport configuration.
func DefaultConfig() Config {
	return Config{
		MaxContentLength: maxContentLength,
		ReadTimeout:      DefaultReadTimeout,
		WriteTimeout:     DefaultWriteTimeout,
	}
}

// Transport handles reading and writing LSP messages.
type Transport struct {
	reader  *bufio.Reader
	writer  io.Writer
	mu      sync.Mutex
	config  Config
	msgChan chan *protocol.Message
	errChan chan error
}

// New creates a new Transport with the given reader and writer.
func New(reader io.Reader, writer io.Writer) *Transport {
	return NewWithConfig(reader, writer, DefaultConfig())
}

// NewWithConfig creates a new Transport with custom configuration.
func NewWithConfig(reader io.Reader, writer io.Writer, cfg Config) *Transport {
	if cfg.MaxContentLength <= 0 {
		cfg.MaxContentLength = maxContentLength
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = DefaultReadTimeout
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = DefaultWriteTimeout
	}
	return &Transport{
		reader:  bufio.NewReader(reader),
		writer:  writer,
		config:  cfg,
		msgChan: make(chan *protocol.Message),
		errChan: make(chan error),
	}
}

// ReadMessage reads a JSON-RPC message from the input.
// This is the synchronous version that blocks until a message is read.
func (t *Transport) ReadMessage() (*protocol.Message, error) {
	return t.readMessageInternal()
}

// ReadMessageWithContext reads a JSON-RPC message with context support.
// Returns an error if the context is cancelled or times out.
func (t *Transport) ReadMessageWithContext(ctx context.Context) (*protocol.Message, error) {
	// Create a channel for the result
	type result struct {
		msg *protocol.Message
		err error
	}
	resultChan := make(chan result, 1)

	// Read in a goroutine
	go func() {
		msg, err := t.readMessageInternal()
		resultChan <- result{msg, err}
	}()

	// Wait for result or context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resultChan:
		return res.msg, res.err
	}
}

// readMessageInternal does the actual message reading.
func (t *Transport) readMessageInternal() (*protocol.Message, error) {
	var contentLength int
	var parseErr error

	// Read headers
	for {
		line, err := t.reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if strings.HasPrefix(line, "Content-Length:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "Content-Length:"))
			contentLength, parseErr = strconv.Atoi(val)
			if parseErr != nil {
				return nil, fmt.Errorf("invalid Content-Length value: %s", val)
			}
		}
	}

	if contentLength == 0 {
		return nil, fmt.Errorf("missing Content-Length header")
	}

	if contentLength < 0 || contentLength > t.config.MaxContentLength {
		return nil, fmt.Errorf(
			"Content-Length %d exceeds maximum allowed size of %d bytes",
			contentLength, t.config.MaxContentLength,
		)
	}

	// Read body
	body := make([]byte, contentLength)
	_, err := io.ReadFull(t.reader, body)
	if err != nil {
		return nil, err
	}

	var msg protocol.Message
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, err
	}

	return &msg, nil
}

// WriteMessage writes a JSON-RPC message to the output.
func (t *Transport) WriteMessage(msg *protocol.Message) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body))
	if _, err := t.writer.Write([]byte(header)); err != nil {
		return err
	}
	if _, err := t.writer.Write(body); err != nil {
		return err
	}

	return nil
}
