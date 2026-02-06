# Falco Rules Language Tooling - Language Server, CLI, and VS Code Extension

<p align="center">
  <img src="vscode-extension/icons/falco.png" alt="Falco Rules" width="128" height="128">
</p>

> UNOFFICIAL language tooling for Falco security rules.

[![CI](https://github.com/c2ndev/falco-lsp/workflows/Falco%20LSP%20CI/badge.svg)](https://github.com/c2ndev/falco-lsp/actions)
[![Build](https://github.com/c2ndev/falco-lsp/workflows/Build%20Binaries/badge.svg)](https://github.com/c2ndev/falco-lsp/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## Overview

This repository provides comprehensive language tooling for [Falco](https://falco.org) security rules:

- **Language Server (LSP)** - Editor-agnostic intelligence with real-time validation
- **CLI Tool** - Validation and formatting from the command line
- **VS Code Extension** - Rich IDE experience with syntax highlighting, completions, and diagnostics
- **Full YAML Support** - 100% compatible with existing `.yaml`/`.yml` Falco rules

## Features

- ✅ **Real-time Validation** - Syntax and semantic error detection as you type
- ✅ **Smart Completions** - Context-aware suggestions for fields, macros, and lists
- ✅ **Go-to-Definition** - Jump to macro and list definitions
- ✅ **Hover Information** - Field documentation and macro/list previews
- ✅ **Syntax Highlighting** - Accurate highlighting for conditions and rule structure
- ✅ **Cross-platform** - Works on Linux, macOS, and Windows

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        CONSUMERS                              │
├─────────────────┬──────────────────┬────────────────────────┤
│   VS Code       │    CLI Tool      │    Other Editors       │
│   Extension     │                  │    (Neovim, etc.)      │
└────────┬────────┴────────┬─────────┴───────────┬────────────┘
         │                 │                     │
         └─────────────────┴─────────────────────┘
                           │
             ┌─────────────▼─────────────┐
             │   Go Language Server      │
             │   ┌─────────────────────┐ │
             │   │  YAML Parser        │ │
             │   ├─────────────────────┤ │
             │   │  Condition Parser   │ │
             │   ├─────────────────────┤ │
             │   │  Semantic Analyzer  │ │
             │   ├─────────────────────┤ │
             │   │  LSP Protocol       │ │
             │   └─────────────────────┘ │
             └───────────────────────────┘
```

## Quick Start

### VS Code Extension

Install from the VS Code Marketplace:

1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X)
3. Search for "Falco Rules"
4. Click Install

Or from command line:

```bash
code --install-extension c2ndev.falco-rules
```

### CLI Tool

#### Build from Source

```bash
# Clone the repository
git clone https://github.com/c2ndev/falco-lsp.git
cd falco-lsp/falco-lsp

# Build
make build

# Or manually
go build -o build/falco-lang ./cmd/falco-lang

# Install to GOPATH
make install
```

#### Usage

```bash
# Validate Falco rules
falco-lang validate ./rules/

# Validate specific files
falco-lang validate file1.yaml file2.yaml

# Format rules (check mode)
falco-lang format ./rules/

# Format rules (write in place)
falco-lang format --write ./rules/
```

## Project Structure

```
├── falco-lsp/                   # Language Server (Go)
│   ├── cmd/falco-lang/          # CLI entry point
│   ├── internal/
│   │   ├── analyzer/            # Semantic analysis
│   │   ├── ast/                 # AST definitions
│   │   ├── condition/           # Condition expression parser
│   │   ├── fields/              # Falco field definitions
│   │   ├── lexer/               # Tokenizer
│   │   ├── lsp/                 # Language Server Protocol
│   │   └── parser/              # YAML rule parser
│   ├── Makefile                 # Build system
│   └── README.md
├── vscode-extension/            # VS Code Extension (TypeScript)
│   ├── src/                     # Extension source code
│   ├── schemas/                 # JSON schemas
│   ├── syntaxes/                # TextMate grammars
│   ├── snippets/                # Code snippets
│   ├── scripts/                 # Sync scripts
│   └── package.json
├── examples/                    # Example Falco rules
└── schema/                      # Shared JSON schemas
```

## Supported Falco Constructs

### Rules

```yaml
- rule: Detect Shell in Container
  desc: Detects when a shell is spawned inside a container
  condition: spawned_process and container and proc.name in (shell_binaries)
  output: "Shell spawned in container (user=%user.name container=%container.name)"
  priority: WARNING
  tags: [container, shell, mitre_execution]
```

### Macros

```yaml
- macro: container
  condition: container.id != host

- macro: spawned_process
  condition: evt.type in (execve, execveat) and evt.dir = <
```

### Lists

```yaml
- list: shell_binaries
  items: [bash, sh, zsh, dash, csh, tcsh, ksh, ash]
```

## Development

### Building

```bash
# Build Go language server
cd falco-lsp
make build

# Run tests
make test

# Build VS Code extension
cd vscode-extension
npm install && npm run build
```

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting a pull request.

1. Fork the repository
2. Create a feature branch
3. Make your changes and add tests
4. Submit a pull request

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

## Related Projects

- [Falco](https://github.com/falcosecurity/falco) - Cloud Native Runtime Security
- [falcoctl](https://github.com/falcosecurity/falcoctl) - Administrative tooling for Falco
- [Falco Rules](https://github.com/falcosecurity/rules) - Official Falco rules repository
