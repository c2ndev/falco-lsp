# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-01-14

### Added

- Initial release of Falco LSP
- Language Server Protocol implementation for Falco rules
- Full LSP features:
  - Code completion for rules, macros, lists, fields, and operators
  - Hover information for Falco fields with documentation
  - Go-to-definition for macros and lists
  - Find references functionality
  - Document symbols outline
  - Real-time diagnostics and validation
- CLI tool (`falco-lang`) with commands:
  - `lsp` - Start LSP server
  - `validate` - Validate Falco rules files
  - `format` - Format Falco rules files
  - `check` - Check formatting without modifying files
- Comprehensive parser for Falco YAML rules
- Condition expression parser with full AST support
- Code formatter with configurable options
- Multi-platform support (Linux, macOS, Windows)
- Cross-architecture builds (amd64, arm64)
- Extensive test coverage (>85% overall)
- Integration tests with official Falco rules

[Unreleased]: https://github.com/c2ndev/falco-lsp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/c2ndev/falco-lsp/releases/tag/v0.1.0
