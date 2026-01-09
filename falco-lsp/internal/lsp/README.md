# LSP Package Architecture

The Language Server Protocol (LSP) implementation is organized into modular sub-packages for maintainability and testability.

## Package Structure

```
lsp/
├── server.go              # Main LSP server, message dispatch
├── server_test.go         # Server unit tests
├── integration_test.go    # End-to-end integration tests
│
├── protocol/              # LSP types and utilities
│   ├── types.go           # All LSP protocol types
│   ├── utils.go           # Position/Range utilities
│   └── protocol_test.go
│
├── document/              # Document management
│   ├── document.go        # Document struct and Store
│   └── document_test.go
│
├── logging/               # LSP-specific logging
│   ├── logger.go          # JSON logger to stderr
│   └── logger_test.go
│
└── providers/             # Feature providers
    ├── base.go            # Dependencies struct (shared deps)
    │
    ├── completion/        # textDocument/completion
    │   ├── completion.go
    │   └── completion_test.go
    │
    ├── diagnostics/       # Diagnostics publishing
    │   ├── diagnostics.go
    │   └── diagnostics_test.go
    │
    ├── hover/             # textDocument/hover
    │   ├── hover.go
    │   └── hover_test.go
    │
    ├── definition/        # textDocument/definition
    │   ├── definition.go
    │   └── definition_test.go
    │
    ├── references/        # textDocument/references
    │   ├── references.go
    │   └── references_test.go
    │
    ├── symbols/           # textDocument/documentSymbol
    │   ├── symbols.go
    │   └── symbols_test.go
    │
    └── formatting/        # textDocument/formatting
        ├── formatting.go
        └── formatting_test.go
```

## Package Descriptions

### `protocol/`

Contains all LSP protocol types and constants:

- **types.go**: Request/response types, method constants, capability structs
- **utils.go**: `GetWordRangeAtPosition`, `PositionToOffset`, `OffsetToPosition`

### `document/`

Thread-safe document storage:

- **Document**: Represents an open file with URI, content, version, and parsed result
- **Store**: Concurrent-safe map of URI → Document with `Get`, `Set`, `Delete`, `All`

### `logging/`

LSP-specific logging that outputs JSON to stderr (to not interfere with stdio JSON-RPC):

- **Init(logFile)**: Initialize logger (empty string = stderr)
- **Debug/Info/Warn/Error**: Log at different levels

### `providers/`

Each feature has its own package with consistent API:

```go
// All providers follow this pattern:
provider := NewProvider(docs *document.Store, analyzer *analyzer.Analyzer)
result := provider.Handle(doc *document.Document, params RequestParams)
```

| Provider      | Constructor                      | Main Method                   |
| ------------- | -------------------------------- | ----------------------------- |
| `completion`  | `New(docs, analyzer)`            | `GetCompletions(doc, params)` |
| `diagnostics` | `New(docs, analyzer, publishFn)` | `Analyze(doc)`                |
| `hover`       | `New(docs, analyzer)`            | `GetHover(doc, params)`       |
| `definition`  | `New(docs, analyzer)`            | `GetDefinition(doc, params)`  |
| `references`  | `New(docs, analyzer)`            | `GetReferences(doc, params)`  |
| `symbols`     | `New(docs, analyzer)`            | `GetDocumentSymbols(doc)`     |
| `formatting`  | `New(docs)`                      | `Format(doc, opts)`           |

### Dependencies

The `providers/base.go` defines a shared `Dependencies` struct, but providers accept dependencies directly in their constructors for explicit dependency injection.

## Data Flow

```
                    ┌─────────────────────────────────────────┐
                    │              server.go                   │
                    │  ┌─────────────────────────────────────┐ │
 stdio JSON-RPC ───▶│  │  Message Dispatch (handleMessage)  │ │
                    │  └─────────────────────────────────────┘ │
                    │         │                                 │
                    │         ▼                                 │
                    │  ┌─────────────────────────────────────┐ │
                    │  │        document.Store               │ │
                    │  │   (thread-safe document storage)    │ │
                    │  └─────────────────────────────────────┘ │
                    │         │                                 │
                    │         ▼                                 │
                    │  ┌─────────────────────────────────────┐ │
                    │  │          providers/*                │ │
                    │  │   completion, hover, definition...  │ │
                    │  └─────────────────────────────────────┘ │
                    │         │                                 │
                    │         ▼                                 │
 stdio JSON-RPC ◀───│      Response                            │
                    └─────────────────────────────────────────┘
```

## Testing

```bash
go test ./internal/lsp/...
go test -v -race ./internal/lsp/...
```

## Adding a New Provider

1. Create a package under `providers/`:

   ```bash
   mkdir -p internal/lsp/providers/newfeature
   ```

2. Implement the provider following the pattern in existing providers.

3. Register in `server.go` and add method dispatch in `handleMessage()`.
