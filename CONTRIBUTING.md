# Contributing to Falco LSP

Thank you for your interest in contributing to the Falco LSP project! This document provides guidelines and instructions for contributing.

## Code of Conduct

This project follows the [CNCF Code of Conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md).

## How to Contribute

### Reporting Issues

- Use the [GitHub issue tracker](https://github.com/falcosecurity/falco-lsp/issues)
- Search existing issues before creating a new one
- Provide as much detail as possible:
  - Steps to reproduce
  - Expected vs actual behavior
  - Version information
  - Relevant logs or screenshots

### Submitting Changes

1. **Fork the repository** and create a feature branch from `main`
2. **Make your changes** following our coding standards
3. **Write or update tests** for your changes
4. **Run the test suite** to ensure all tests pass
5. **Submit a pull request** with a clear description

### Development Setup

```bash
# Clone the repository
git clone https://github.com/falcosecurity/falco-lsp.git
cd falco-lsp

# Build the language server
cd falco-lsp
make build

# Run tests
make test

# Run linter
make lint
```

### Coding Standards

#### Go Code

- Follow [Effective Go](https://golang.org/doc/effective_go) guidelines
- Run `golangci-lint run` before committing
- Write tests for new functionality
- Use meaningful variable and function names
- Add comments for exported functions

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Examples:

```
feat(lsp): add hover support for macros
fix(parser): handle empty condition strings
docs(readme): update installation instructions
```

### Pull Request Process

1. Update documentation if needed
2. Add tests for new features
3. Ensure CI passes
4. Request review from maintainers
5. Address review feedback promptly

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
│   └── package.json
├── examples/                    # Example Falco rules
└── schema/                      # Shared JSON schemas
```

## Testing

### Go Tests

```bash
make test                        # Run all tests
make test-cover                  # With coverage
go test -race ./...              # With race detection
```

## Release Process

Releases are managed via git tags:

1. Update version in code if needed
2. Create a git tag: `git tag v1.2.3`
3. Push the tag: `git push origin v1.2.3`

## Getting Help

- [GitHub Issues](https://github.com/falcosecurity/falco-lsp/issues)
- [GitHub Discussions](https://github.com/falcosecurity/falco-lsp/discussions)

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
