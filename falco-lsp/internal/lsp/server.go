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

package lsp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/c2ndev/falco-lsp/internal/config"
	"github.com/c2ndev/falco-lsp/internal/lsp/document"
	"github.com/c2ndev/falco-lsp/internal/lsp/handlers"
	"github.com/c2ndev/falco-lsp/internal/lsp/logging"
	"github.com/c2ndev/falco-lsp/internal/lsp/protocol"
	"github.com/c2ndev/falco-lsp/internal/lsp/providers/completion"
	"github.com/c2ndev/falco-lsp/internal/lsp/providers/definition"
	"github.com/c2ndev/falco-lsp/internal/lsp/providers/formatting"
	"github.com/c2ndev/falco-lsp/internal/lsp/providers/hover"
	"github.com/c2ndev/falco-lsp/internal/lsp/providers/references"
	"github.com/c2ndev/falco-lsp/internal/lsp/providers/symbols"
	"github.com/c2ndev/falco-lsp/internal/lsp/router"
	"github.com/c2ndev/falco-lsp/internal/lsp/transport"
	"github.com/c2ndev/falco-lsp/internal/version"
)

// Server represents an LSP server for Falco rules.
type Server struct {
	transport *transport.Transport
	router    *router.Router
	handlers  *handlers.Handlers

	// Server state
	shutdown bool
	cancel   context.CancelFunc
}

// NewServer creates a new LSP server.
func NewServer() *Server {
	return NewServerWithTransport(transport.New(os.Stdin, os.Stdout))
}

// NewServerWithTransport creates a new LSP server with a custom transport.
// This is primarily used for testing.
func NewServerWithTransport(t *transport.Transport) *Server {
	r := router.New()

	s := &Server{
		transport: t,
		router:    r,
	}

	// Load runtime configuration from environment
	rtConfig := config.FromEnvironment()

	// Create handlers with callbacks and configuration
	cfg := handlers.Config{
		RuntimeConfig: rtConfig,
		PublishDiagFn: s.publishDiagnostics,
		OnShutdown:    func() { s.shutdown = true },
	}
	s.handlers = handlers.New(cfg)
	s.handlers.Register(r)

	logging.Info("LSP server initialized", "version", version.Version)
	return s
}

// Run starts the LSP server main loop with context support for graceful shutdown.
func (s *Server) Run() error {
	return s.RunWithContext(context.Background())
}

// RunWithContext starts the LSP server main loop with the provided context.
// The server will stop when the context is canceled.
func (s *Server) RunWithContext(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	defer cancel()

	// Handle OS signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-sigChan:
			logging.Info("Received shutdown signal")
			cancel()
		case <-ctx.Done():
		}
	}()

	// Message processing loop
	msgChan := make(chan *protocol.Message)
	errChan := make(chan error, 1)

	go func() {
		for {
			msg, err := s.transport.ReadMessage()
			if err != nil {
				errChan <- err
				return
			}
			select {
			case msgChan <- msg:
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			logging.Info("Context canceled, shutting down")
			return ctx.Err()

		case err := <-errChan:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read error: %w", err)

		case msg := <-msgChan:
			response := s.handleMessage(msg)
			if response != nil {
				if err := s.transport.WriteMessage(response); err != nil {
					return fmt.Errorf("write error: %w", err)
				}
			}

			if s.shutdown {
				logging.Info("Shutdown requested, exiting")
				return nil
			}
		}
	}
}

// handleMessage dispatches a message to the router.
// Special handling for exit which requires immediate termination.
func (s *Server) handleMessage(msg *protocol.Message) *protocol.Message {
	if msg.Method == protocol.MethodExit {
		os.Exit(0)
		return nil
	}
	return s.router.Dispatch(msg)
}

// publishDiagnostics sends diagnostics to the client.
func (s *Server) publishDiagnostics(uri string, docVersion *int, diags []protocol.Diagnostic) {
	params := protocol.PublishDiagnosticsParams{
		URI:         uri,
		Diagnostics: diags,
	}
	if docVersion != nil {
		params.Version = docVersion
	}

	data, err := json.Marshal(params)
	if err != nil {
		logging.Error("Failed to marshal diagnostics params", "error", err)
		return
	}
	notification := protocol.NewNotification(protocol.MethodPublishDiagnostics, data)

	if err := s.transport.WriteMessage(notification); err != nil {
		logging.Error("Failed to publish diagnostics", "error", err)
	}
}

// InitLogger initializes the LSP logger.
func InitLogger(logFile string, level int) error {
	return logging.Init(logFile, logging.Level(level))
}

// Test accessors - these provide access to internal components for testing.

// Documents returns the document store (for testing).
func (s *Server) Documents() *document.Store {
	return s.handlers.GetDocuments()
}

// Completion returns the completion provider (for testing).
func (s *Server) Completion() *completion.Provider {
	return s.handlers.GetCompletion()
}

// Hover returns the hover provider (for testing).
func (s *Server) Hover() *hover.Provider {
	return s.handlers.GetHover()
}

// Definition returns the definition provider (for testing).
func (s *Server) Definition() *definition.Provider {
	return s.handlers.GetDefinition()
}

// Symbols returns the symbols provider (for testing).
func (s *Server) Symbols() *symbols.Provider {
	return s.handlers.GetSymbols()
}

// References returns the references provider (for testing).
func (s *Server) References() *references.Provider {
	return s.handlers.GetReferences()
}

// Formatting returns the formatting provider (for testing).
func (s *Server) Formatting() *formatting.Provider {
	return s.handlers.GetFormatting()
}
