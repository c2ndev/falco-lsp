# Falco LSP - Language Server for Falco Rules

A modern Language Server Protocol (LSP) implementation for Falco security rules, providing:

- **Language Server** with full LSP support for IDE integration
- **CLI tool** (`falco-lang`) for validating and formatting Falco rules
- **Go library** for programmatic access to parsing and validation

## Installation

### From Source

```bash
cd falco-lsp
make build
./build/falco-lang --help
```

### Install to GOPATH

```bash
make install
falco-lang --help
```

## Usage

### Validate Rules

```bash
# Validate a single file
falco-lang validate rules.yaml

# Validate multiple files
falco-lang validate *.yaml

# Validate an entire directory (recursive)
falco-lang validate ./rules/

# JSON output for CI/CD
falco-lang validate --format json rules.yaml

# Strict mode (warnings are errors)
falco-lang validate --strict rules.yaml
```

### Format Rules

```bash
# Check formatting
falco-lang format --check rules.yaml

# Format in place
falco-lang format --write rules.yaml

# Show diff of formatting changes
falco-lang format --check --diff rules.yaml

# Custom indentation (default: 2 spaces)
falco-lang format --write --tab-size 4 rules.yaml
```

### Start LSP Server

```bash
# stdio mode (default, for IDE integration)
falco-lang lsp --stdio
```

Compatible with any LSP-capable editor (VS Code, Neovim, Emacs, etc.).

## Library Usage

For integration with other Go programs:

```go
import "github.com/c2ndev/falco-lsp/pkg/falco"

// Parse a rules file
content := `
- rule: Test Rule
  desc: A test rule
  condition: proc.name = bash
  output: "Process executed"
  priority: WARNING
`

result, err := falco.Parse(content, "rules.yaml")
if err != nil {
    log.Fatal(err)
}

// Validate a rules file
diagnostics, err := falco.Validate(content, "rules.yaml")
if err != nil {
    log.Fatal(err)
}

for _, d := range diagnostics {
    fmt.Printf("%s: %s\n", d.Severity, d.Message)
}
```

## Architecture

```
falco-lsp/
├── cmd/
│   └── falco-lang/              # CLI entry point
│       └── main.go
├── internal/
│   ├── ast/                     # AST types for condition expressions
│   │   └── ast.go
│   ├── lexer/                   # Tokenizer for condition expressions
│   │   ├── lexer.go
│   │   └── lexer_test.go
│   ├── condition/               # Parser for condition expressions
│   │   ├── parser.go
│   │   └── parser_test.go
│   ├── parser/                  # YAML parser for Falco rules files
│   │   ├── parser.go
│   │   └── parser_test.go
│   ├── fields/                  # Falco field definitions (generated)
│   │   └── fields_generated.go
│   ├── analyzer/                # Semantic analyzer
│   │   ├── analyzer.go
│   │   ├── collector.go
│   │   ├── validation.go
│   │   └── analyzer_test.go
│   ├── formatter/               # Code formatter
│   │   ├── formatter.go
│   │   └── formatter_test.go
│   └── lsp/                     # Language Server Protocol implementation
│       ├── server.go            # Main LSP server
│       ├── protocol/            # LSP types, constants, utilities
│       │   ├── types.go
│       │   └── utils.go
│       ├── document/            # Document management (open/change/close)
│       │   └── document.go
│       ├── logging/             # LSP-specific logging
│       │   └── logger.go
│       ├── transport/           # LSP transport layer
│       │   └── transport.go
│       ├── router/              # Message routing
│       │   └── router.go
│       ├── handlers/            # LSP message handlers
│       │   └── handlers.go
│       └── providers/           # LSP feature providers
│           ├── base.go          # Shared dependencies struct
│           ├── completion/      # textDocument/completion
│           ├── diagnostics/     # Diagnostics publishing
│           ├── hover/           # textDocument/hover
│           ├── definition/      # textDocument/definition
│           ├── references/      # textDocument/references
│           ├── symbols/         # textDocument/documentSymbol
│           └── formatting/      # textDocument/formatting
├── Makefile                     # Build system
├── .golangci.yml                # Linter configuration (v2)
└── README.md                    # This file
```

### LSP Sub-packages

The LSP implementation is organized into logical sub-packages:

| Package      | Description                                                              |
| ------------ | ------------------------------------------------------------------------ |
| `protocol/`  | LSP types, method constants, and utilities (Position/Range manipulation) |
| `document/`  | Thread-safe document store with incremental sync support                 |
| `logging/`   | LSP-specific logging to stderr (JSON format)                             |
| `providers/` | Feature providers, each in its own package                               |

Each provider follows a consistent pattern:

```go
// Constructor
provider := completion.New(documentStore, analyzer)

// Handle request
items := provider.GetCompletions(doc, params)
```

## Development

### Prerequisites

- Go 1.22 or later
- golangci-lint (installed automatically by `make lint`)

### Commands

```bash
# Build
make build

# Run tests
make test

# Run tests with coverage
make test-cover

# Lint
make lint

# Format code
make fmt

# Build for all platforms
make build-all

# Clean build artifacts
make clean
```

### Running Tests

```bash
# All tests
go test ./...

# Specific package
go test ./internal/lexer/...

# With verbose output
go test -v ./...

# With race detection
go test -race ./...
```

## License

Apache License 2.0
