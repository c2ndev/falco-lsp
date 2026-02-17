# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-02-06

### Added

- First-class support for `*_rules.yaml` and `*_rules.yml` files (official Falco naming convention, e.g., `falco_rules.yaml`, `k8s_audit_rules.yaml`)
- VS Code activation, language detection, schema validation, file watching, and workspace validation for `*_rules.yaml`/`*_rules.yml`
- CLI directory scanning picks up `*_rules.yaml`/`*_rules.yml` alongside `*.falco.yaml`/`*.falco.yml`
- Tests for `isFalcoFile()` and `expandPatterns()` directory walk

### Changed

- CLI `isFalcoFile()` no longer matches generic `.yaml`/`.yml` files; only recognized Falco patterns are matched
- Rewrote `vscode-extension/CHANGELOG.md` to reflect actual release history

## [0.1.0] - 2026-02-06

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
  - `format` - Format Falco rules files (with `--check` flag for dry-run)
  - `version` - Print version information
- Comprehensive parser for Falco YAML rules
- Condition expression parser with full AST support
- Code formatter with configurable options
- VS Code extension with syntax highlighting, snippets, and JSON schema validation
- Multi-platform support (Linux, macOS, Windows)
- Cross-architecture builds (amd64, arm64)
- Extensive test coverage (>85% overall)

[Unreleased]: https://github.com/falcosecurity/falco-lsp/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/falcosecurity/falco-lsp/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/falcosecurity/falco-lsp/releases/tag/v0.1.0
