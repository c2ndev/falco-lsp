# Changelog

All notable changes to the Falco Rules VS Code extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Refactored LSP server into modular architecture for better maintainability
- Improved diagnostics refresh - errors now properly clear when fixed
- Enhanced code completion with better context awareness
- Updated extension to support both `.falco` and `.falco.yaml` files consistently

### Fixed

- Fixed stale diagnostics not clearing when errors are corrected
- Fixed duplicate diagnostics appearing after multiple edits
- Fixed completion items duplicating dashes when triggered after `-`

### Removed

- Removed deprecated `falco.convertDslToYaml` command

## [0.2.3] - 2024-01-15

### Added

- Initial public release
- Syntax highlighting for Falco rules
- Code completion for rules, macros, lists, and fields
- Hover information for Falco fields
- Go-to-definition for macros and lists
- Real-time diagnostics and validation
- JSON Schema validation for YAML files
- Snippets for common rule patterns

### Technical

- Go-based language server with LSP protocol
- Full support for `.falco.yaml` and `.falco.yml` files
- Cross-platform binary support (Linux, macOS, Windows)

---

## Version History

### Pre-release versions

Development versions prior to 0.2.3 were internal releases for testing and validation.

---

[Unreleased]: https://github.com/c2ndev/falco-lsp/compare/v0.2.3...HEAD
[0.2.3]: https://github.com/c2ndev/falco-lsp/releases/tag/v0.2.3
