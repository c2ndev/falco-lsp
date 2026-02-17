# Changelog

All notable changes to the Falco Rules VS Code extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-02-06

### Added

- First-class support for `*_rules.yaml` and `*_rules.yml` files (official Falco naming convention, e.g., `falco_rules.yaml`, `k8s_audit_rules.yaml`)
- VS Code activation, language detection, schema validation, file watching, and workspace validation for `*_rules.yaml`/`*_rules.yml`
- CLI directory scanning picks up `*_rules.yaml`/`*_rules.yml` alongside `*.falco.yaml`/`*.falco.yml`

### Changed

- CLI `isFalcoFile()` no longer matches generic `.yaml`/`.yml` files; only recognized Falco patterns are matched

## [0.1.0] - 2026-02-06

### Added

- Syntax highlighting for Falco rules (`.falco.yaml`, `.falco.yml`)
- Intelligent code completion for rules, macros, lists, fields, operators, priorities, and sources
- Hover information for Falco fields and user-defined symbols
- Go-to-definition for macros, lists, and rules
- Find references for macros and lists across files
- Document symbols outline
- Real-time diagnostics and semantic validation
- JSON Schema validation for Falco YAML files
- Code formatting with configurable indentation
- Snippets for common rule patterns
- Workspace-wide validation command
- Cross-platform Go language server (Linux, macOS, Windows)
- CLI tool (`falco-lang`) with validate, format, and lsp commands

[Unreleased]: https://github.com/falcosecurity/falco-lsp/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/falcosecurity/falco-lsp/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/falcosecurity/falco-lsp/releases/tag/v0.1.0
