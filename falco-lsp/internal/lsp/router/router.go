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
	"github.com/falcosecurity/falco-lsp/internal/lsp/protocol"
)

// Handler is a function that handles an LSP message and returns a response.
type Handler func(msg *protocol.Message) *protocol.Message

// NotificationHandler is a function that handles an LSP notification (no response).
type NotificationHandler func(msg *protocol.Message)

// Router dispatches LSP messages to appropriate handlers.
type Router struct {
	handlers             map[protocol.Method]Handler
	notificationHandlers map[protocol.Method]NotificationHandler
}

// New creates a new Router.
func New() *Router {
	return &Router{
		handlers:             make(map[protocol.Method]Handler),
		notificationHandlers: make(map[protocol.Method]NotificationHandler),
	}
}

// RegisterHandler registers a handler for a request method.
func (r *Router) RegisterHandler(method protocol.Method, handler Handler) {
	r.handlers[method] = handler
}

// RegisterNotification registers a handler for a notification method.
func (r *Router) RegisterNotification(method protocol.Method, handler NotificationHandler) {
	r.notificationHandlers[method] = handler
}

// Dispatch routes a message to the appropriate handler.
// Returns a response message for requests, or nil for notifications.
func (r *Router) Dispatch(msg *protocol.Message) *protocol.Message {
	// Check for request handler
	if handler, ok := r.handlers[msg.Method]; ok {
		return handler(msg)
	}

	// Check for notification handler
	if handler, ok := r.notificationHandlers[msg.Method]; ok {
		handler(msg)
		return nil
	}

	// Unknown method - return error for requests, ignore notifications
	if msg.ID != nil {
		return protocol.NewErrorResponse(msg.ID, protocol.ErrorCodeMethodNotFound,
			"Method not found: "+msg.Method.String())
	}

	return nil
}

// HasHandler returns true if a handler is registered for the method.
func (r *Router) HasHandler(method protocol.Method) bool {
	_, hasReq := r.handlers[method]
	_, hasNotif := r.notificationHandlers[method]
	return hasReq || hasNotif
}
