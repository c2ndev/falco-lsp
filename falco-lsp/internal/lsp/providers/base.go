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

package providers

import (
	"github.com/c2ndev/falco-lsp/internal/lsp/document"
)

// Dependencies holds the common dependencies for all providers.
type Dependencies struct {
	Documents *document.Store
}

// NewDependencies creates a new Dependencies instance.
func NewDependencies(docs *document.Store) *Dependencies {
	return &Dependencies{
		Documents: docs,
	}
}

// Base provides common functionality for all LSP providers.
type Base struct {
	deps *Dependencies
}

// NewBase creates a new base provider.
func NewBase(deps *Dependencies) Base {
	return Base{deps: deps}
}

// GetDocument retrieves a document by URI.
func (b *Base) GetDocument(uri string) (*document.Document, bool) {
	return b.deps.Documents.Get(uri)
}

// GetDocuments returns the document store.
func (b *Base) GetDocuments() *document.Store {
	return b.deps.Documents
}
