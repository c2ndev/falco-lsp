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

package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/c2ndev/falco-lsp/internal/config"
	"github.com/c2ndev/falco-lsp/internal/lsp/document"
	"github.com/c2ndev/falco-lsp/internal/lsp/logging"
	"github.com/c2ndev/falco-lsp/internal/lsp/protocol"
	"github.com/c2ndev/falco-lsp/internal/lsp/providers/completion"
	"github.com/c2ndev/falco-lsp/internal/lsp/providers/definition"
	"github.com/c2ndev/falco-lsp/internal/lsp/providers/diagnostics"
	"github.com/c2ndev/falco-lsp/internal/lsp/providers/formatting"
	"github.com/c2ndev/falco-lsp/internal/lsp/providers/hover"
	"github.com/c2ndev/falco-lsp/internal/lsp/providers/references"
	"github.com/c2ndev/falco-lsp/internal/lsp/providers/symbols"
	"github.com/c2ndev/falco-lsp/internal/lsp/router"
	"github.com/c2ndev/falco-lsp/internal/version"
)

// Handlers contains all LSP handlers and their dependencies.
type Handlers struct {
	documents   *document.Store
	logger      *slog.Logger
	diagnostics *diagnostics.Provider
	completion  *completion.Provider
	hover       *hover.Provider
	definition  *definition.Provider
	symbols     *symbols.Provider
	references  *references.Provider
	formatting  *formatting.Provider

	// Callbacks
	onInitialized func()
	onShutdown    func()
}

// Config holds configuration for handlers.
type Config struct {
	// Runtime configuration from config package
	RuntimeConfig *config.Config

	// Dependency injection
	Documents     *document.Store
	Logger        *slog.Logger
	PublishDiagFn diagnostics.PublishFunc

	// Callbacks
	OnInitialized func()
	OnShutdown    func()
}

// New creates a new Handlers instance.
func New(cfg Config) *Handlers {
	docs := cfg.Documents
	if docs == nil {
		docs = document.NewStore()
	}

	// Use default runtime config if not provided
	rtCfg := cfg.RuntimeConfig
	if rtCfg == nil {
		rtCfg = config.DefaultConfig()
	}

	h := &Handlers{
		documents:     docs,
		logger:        cfg.Logger,
		onInitialized: cfg.OnInitialized,
		onShutdown:    cfg.OnShutdown,
	}

	if h.logger == nil {
		h.logger = slog.Default()
	}

	// Initialize providers with configuration
	h.diagnostics = diagnostics.New(docs, cfg.PublishDiagFn, rtCfg.MaxDiagnostics)
	h.completion = completion.New(docs, rtCfg.MaxCompletionItems)
	h.hover = hover.New(docs)
	h.definition = definition.New(docs)
	h.symbols = symbols.New(docs)
	h.references = references.New(docs)
	h.formatting = formatting.New(docs, rtCfg.TabSize)

	return h
}

// Register registers all handlers with the router.
func (h *Handlers) Register(r *router.Router) {
	// Lifecycle
	r.RegisterHandler(protocol.MethodInitialize, h.HandleInitialize)
	r.RegisterNotification(protocol.MethodInitialized, h.HandleInitialized)
	r.RegisterHandler(protocol.MethodShutdown, h.HandleShutdown)

	// Document sync
	r.RegisterNotification(protocol.MethodTextDocumentDidOpen, h.HandleDidOpen)
	r.RegisterNotification(protocol.MethodTextDocumentDidChange, h.HandleDidChange)
	r.RegisterNotification(protocol.MethodTextDocumentDidClose, h.HandleDidClose)
	r.RegisterNotification(protocol.MethodTextDocumentDidSave, h.HandleDidSave)
	r.RegisterNotification(protocol.MethodWorkspaceDidChangeWatchedFiles, h.HandleDidChangeWatchedFiles)

	// Language features
	r.RegisterHandler(protocol.MethodTextDocumentCompletion, h.HandleCompletion)
	r.RegisterHandler(protocol.MethodTextDocumentHover, h.HandleHover)
	r.RegisterHandler(protocol.MethodTextDocumentDefinition, h.HandleDefinition)
	r.RegisterHandler(protocol.MethodTextDocumentReferences, h.HandleReferences)
	r.RegisterHandler(protocol.MethodTextDocumentDocumentSymbol, h.HandleDocumentSymbol)
	r.RegisterHandler(protocol.MethodTextDocumentFormatting, h.HandleFormatting)
	r.RegisterHandler(protocol.MethodTextDocumentRangeFormatting, h.HandleRangeFormatting)
}

// HandleInitialize handles the initialize request.
func (h *Handlers) HandleInitialize(msg *protocol.Message) *protocol.Message {
	logging.Info("Handling initialize request")

	result := protocol.InitializeResult{
		Capabilities: protocol.ServerCapabilities{
			TextDocumentSync: &protocol.TextDocumentSyncOptions{
				OpenClose: true,
				Change:    protocol.TextDocumentSyncKindIncremental,
				Save:      &protocol.SaveOptions{IncludeText: false},
			},
			CompletionProvider: &protocol.CompletionOptions{
				TriggerCharacters: protocol.DefaultCompletionTriggerCharacters,
				ResolveProvider:   false,
			},
			HoverProvider:                   true,
			DefinitionProvider:              true,
			ReferencesProvider:              true,
			DocumentSymbolProvider:          true,
			DocumentFormattingProvider:      true,
			DocumentRangeFormattingProvider: true,
		},
		ServerInfo: &protocol.ServerInfo{
			Name:    version.ServerName,
			Version: version.Version,
		},
	}

	return protocol.NewResponse(msg.ID, result)
}

// HandleInitialized handles the initialized notification.
func (h *Handlers) HandleInitialized(_ *protocol.Message) {
	if h.onInitialized != nil {
		h.onInitialized()
	}
}

// HandleShutdown handles the shutdown request.
func (h *Handlers) HandleShutdown(msg *protocol.Message) *protocol.Message {
	if h.onShutdown != nil {
		h.onShutdown()
	}
	// Use NewNullResponse to ensure the result is explicitly null in JSON
	// This is required by the LSP spec for the shutdown response
	return protocol.NewNullResponse(msg.ID)
}

// HandleDidOpen handles textDocument/didOpen notifications.
func (h *Handlers) HandleDidOpen(msg *protocol.Message) {
	var params protocol.DidOpenTextDocumentParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		logging.Warn("Failed to unmarshal didOpen params", "error", err)
		return
	}

	doc := document.NewDocument(
		params.TextDocument.URI,
		params.TextDocument.Text,
		params.TextDocument.Version,
	)

	if err := h.documents.Set(doc); err != nil {
		h.logger.Warn("invalid document URI", "error", err, "uri", params.TextDocument.URI)
		return
	}
	h.diagnostics.AnalyzeAndPublish(doc)
}

// HandleDidChange handles textDocument/didChange notifications.
func (h *Handlers) HandleDidChange(msg *protocol.Message) {
	var params protocol.DidChangeTextDocumentParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		logging.Warn("Failed to unmarshal didChange params", "error", err)
		return
	}

	doc, ok := h.documents.Get(params.TextDocument.URI)
	if !ok {
		doc = document.NewDocument(
			params.TextDocument.URI,
			"",
			params.TextDocument.Version,
		)
	}

	newDoc := doc.ApplyContentChanges(params.ContentChanges, params.TextDocument.Version)
	if err := h.documents.Set(newDoc); err != nil {
		h.logger.Warn("invalid document URI", "error", err, "uri", params.TextDocument.URI)
		return
	}
	h.diagnostics.AnalyzeAndPublish(newDoc)
}

// HandleDidClose handles textDocument/didClose notifications.
func (h *Handlers) HandleDidClose(msg *protocol.Message) {
	var params protocol.DidCloseTextDocumentParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		logging.Warn("Failed to unmarshal didClose params", "error", err)
		return
	}

	h.documents.Delete(params.TextDocument.URI)
	// NOTE: We intentionally do NOT clear diagnostics here
	// Diagnostics persist so Problems panel shows issues even for closed files
}

// HandleDidSave handles textDocument/didSave notifications.
func (h *Handlers) HandleDidSave(msg *protocol.Message) {
	var params protocol.DidSaveTextDocumentParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		logging.Warn("Failed to unmarshal didSave params", "error", err)
		return
	}

	doc, ok := h.documents.Get(params.TextDocument.URI)
	if !ok {
		return
	}

	h.diagnostics.AnalyzeAndPublish(doc)
}

// HandleDidChangeWatchedFiles handles workspace/didChangeWatchedFiles notifications.
// This is sent by the client when watched files are created, changed, or deleted.
func (h *Handlers) HandleDidChangeWatchedFiles(msg *protocol.Message) {
	var params protocol.DidChangeWatchedFilesParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		logging.Warn("Failed to unmarshal didChangeWatchedFiles params", "error", err)
		return
	}

	for _, change := range params.Changes {
		if change.Type == protocol.FileChangeTypeDeleted {
			// File was deleted - clear diagnostics and remove from store.
			h.documents.Delete(change.URI)
			h.diagnostics.ClearDiagnostics(change.URI)
			logging.Debug("Cleared diagnostics for deleted file", "uri", change.URI)
		}
	}
}

// HandleCompletion handles textDocument/completion requests.
func (h *Handlers) HandleCompletion(msg *protocol.Message) *protocol.Message {
	var params protocol.CompletionParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		logging.Warn("Failed to unmarshal completion params", "error", err)
		return h.errorResponse(msg.ID,
			fmt.Sprintf("Invalid completion params: %v", err))
	}

	logging.Debug("Completion request",
		"uri", params.TextDocument.URI,
		"line", params.Position.Line,
		"character", params.Position.Character)

	doc, ok := h.documents.Get(params.TextDocument.URI)
	if !ok {
		logging.Debug("Document not found for completion", "uri", params.TextDocument.URI)
		return protocol.NewResponse(msg.ID, []protocol.CompletionItem{})
	}

	items := h.completion.GetCompletions(doc, params)
	logging.Debug("Completion items returned", "count", len(items))
	return protocol.NewResponse(msg.ID, items)
}

// HandleHover handles textDocument/hover requests.
func (h *Handlers) HandleHover(msg *protocol.Message) *protocol.Message {
	var params protocol.TextDocumentPositionParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		logging.Warn("Failed to unmarshal hover params", "error", err)
		return h.errorResponse(msg.ID,
			fmt.Sprintf("Invalid hover params: %v", err))
	}

	doc, ok := h.documents.Get(params.TextDocument.URI)
	if !ok {
		return protocol.NewResponse(msg.ID, nil)
	}

	hoverResult := h.hover.GetHover(doc, params)
	return protocol.NewResponse(msg.ID, hoverResult)
}

// HandleDefinition handles textDocument/definition requests.
func (h *Handlers) HandleDefinition(msg *protocol.Message) *protocol.Message {
	var params protocol.TextDocumentPositionParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		logging.Warn("Failed to unmarshal definition params", "error", err)
		return h.errorResponse(msg.ID,
			fmt.Sprintf("Invalid definition params: %v", err))
	}

	doc, ok := h.documents.Get(params.TextDocument.URI)
	if !ok {
		return protocol.NewResponse(msg.ID, nil)
	}

	location := h.definition.GetDefinition(doc, params)
	return protocol.NewResponse(msg.ID, location)
}

// HandleReferences handles textDocument/references requests.
func (h *Handlers) HandleReferences(msg *protocol.Message) *protocol.Message {
	var params protocol.ReferenceParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		logging.Warn("Failed to unmarshal references params", "error", err)
		return h.errorResponse(msg.ID,
			fmt.Sprintf("Invalid references params: %v", err))
	}

	doc, ok := h.documents.Get(params.TextDocument.URI)
	if !ok {
		return protocol.NewResponse(msg.ID, []protocol.Location{})
	}

	locations := h.references.GetReferences(doc, params)
	return protocol.NewResponse(msg.ID, locations)
}

// HandleDocumentSymbol handles textDocument/documentSymbol requests.
func (h *Handlers) HandleDocumentSymbol(msg *protocol.Message) *protocol.Message {
	var params protocol.DocumentSymbolParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		logging.Warn("Failed to unmarshal documentSymbol params", "error", err)
		return h.errorResponse(msg.ID,
			fmt.Sprintf("Invalid documentSymbol params: %v", err))
	}

	doc, ok := h.documents.Get(params.TextDocument.URI)
	if !ok {
		return protocol.NewResponse(msg.ID, []protocol.DocumentSymbol{})
	}

	syms := h.symbols.GetDocumentSymbols(doc)
	return protocol.NewResponse(msg.ID, syms)
}

// HandleFormatting handles textDocument/formatting requests.
func (h *Handlers) HandleFormatting(msg *protocol.Message) *protocol.Message {
	var params protocol.DocumentFormattingParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		logging.Warn("Failed to unmarshal formatting params", "error", err)
		return h.errorResponse(msg.ID,
			fmt.Sprintf("Invalid formatting params: %v", err))
	}

	doc, ok := h.documents.Get(params.TextDocument.URI)
	if !ok {
		return protocol.NewResponse(msg.ID, []protocol.TextEdit{})
	}

	edits := h.formatting.Format(doc, params.Options)
	return protocol.NewResponse(msg.ID, edits)
}

// HandleRangeFormatting handles textDocument/rangeFormatting requests.
func (h *Handlers) HandleRangeFormatting(msg *protocol.Message) *protocol.Message {
	var params protocol.DocumentRangeFormattingParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		logging.Warn("Failed to unmarshal rangeFormatting params", "error", err)
		return h.errorResponse(msg.ID,
			fmt.Sprintf("Invalid rangeFormatting params: %v", err))
	}

	doc, ok := h.documents.Get(params.TextDocument.URI)
	if !ok {
		return protocol.NewResponse(msg.ID, []protocol.TextEdit{})
	}

	edits := h.formatting.FormatRange(doc, params)
	return protocol.NewResponse(msg.ID, edits)
}

// GetDocuments returns the document store (for testing).
func (h *Handlers) GetDocuments() *document.Store {
	return h.documents
}

// GetCompletion returns the completion provider (for testing).
func (h *Handlers) GetCompletion() *completion.Provider {
	return h.completion
}

// GetHover returns the hover provider (for testing).
func (h *Handlers) GetHover() *hover.Provider {
	return h.hover
}

// GetDefinition returns the definition provider (for testing).
func (h *Handlers) GetDefinition() *definition.Provider {
	return h.definition
}

// GetSymbols returns the symbols provider (for testing).
func (h *Handlers) GetSymbols() *symbols.Provider {
	return h.symbols
}

// GetReferences returns the references provider (for testing).
func (h *Handlers) GetReferences() *references.Provider {
	return h.references
}

// GetFormatting returns the formatting provider (for testing).
func (h *Handlers) GetFormatting() *formatting.Provider {
	return h.formatting
}

// errorResponse creates a JSON-RPC error response for invalid params.
func (h *Handlers) errorResponse(id interface{}, message string) *protocol.Message {
	return protocol.NewErrorResponse(id, protocol.ErrorCodeInvalidParams, message)
}
