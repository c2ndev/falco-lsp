# Falco Rules for Visual Studio Code

<p align="center">
  <img src="https://raw.githubusercontent.com/falcosecurity/falco-lsp/main/vscode-extension/icons/falco.png" alt="Falco" width="128" height="128">
</p>

<p align="center">
  <strong>Full language support for Falco Security Rules</strong>
</p>

<p align="center">
  <a href="https://marketplace.visualstudio.com/items?itemName=falcosecurity.falco-rules">
    <img src="https://img.shields.io/visual-studio-marketplace/v/falcosecurity.falco-rules?style=flat-square&label=VS%20Marketplace" alt="VS Marketplace Version">
  </a>
  <a href="https://marketplace.visualstudio.com/items?itemName=falcosecurity.falco-rules">
    <img src="https://img.shields.io/visual-studio-marketplace/i/falcosecurity.falco-rules?style=flat-square" alt="Installs">
  </a>
  <a href="https://github.com/falcosecurity/falco-lsp/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square" alt="License">
  </a>
</p>

---

## Features

### 🎨 Syntax Highlighting

Rich syntax highlighting for Falco rules files (`.falco.yaml`, `.falco.yml`, `*_rules.yaml`, `*_rules.yml`) with support for:

- Rule, macro, and list definitions
- Condition expressions with operators
- Field references and string values
- Comments and YAML structure

### 💡 Intelligent Code Completion

Context-aware completions for:

- **Top-level items**: `rule`, `macro`, `list`, `required_engine_version`, `required_plugin_versions`
- **Rule properties**: `condition`, `output`, `priority`, `source`, `tags`, `exceptions`, `enabled`, `desc`, `append`, `override`, `capture`, `capture_duration`, `warn_evttypes`, `skip-if-unknown-filter`
- **Falco fields**: All syscall, container, and Kubernetes fields
- **Operators**: Comparison (`=`, `!=`, `contains`, `icontains`, `in`, `pmatch`, `glob`, `startswith`, `endswith`) and logical (`and`, `or`, `not`)
- **User-defined symbols**: Macros and lists defined in your files
- **Priority levels**: `EMERGENCY`, `ALERT`, `CRITICAL`, `ERROR`, `WARNING`, `NOTICE`, `INFORMATIONAL`, `DEBUG`
- **Sources**: `syscall`, `k8s_audit`, `aws_cloudtrail`, `gcp_auditlog`, `azure_platformlogs`, `github`, `okta`, and more
- **Plugin version properties**: `name`, `version`, `alternatives`

### 🔍 Hover Information

Hover over any element to see detailed information:

- Field descriptions and types
- Macro definitions and conditions
- List contents preview

### 📍 Go to Definition

Jump to the definition of:

- Macros referenced in conditions
- Lists used in expressions
- Rules by name

### ⚡ Real-time Diagnostics

Instant validation as you type:

- **Syntax errors**: Invalid YAML or condition syntax
- **Undefined references**: Unknown macros or lists
- **Field validation**: Unknown or mismatched fields for source type
- **Best practices**: Hints for dynamic fields requiring arguments

### 📋 Snippets

Quick templates for common patterns:

- Complete rule definition with all properties
- Macro with condition
- List with items
- Exception blocks
- Engine version requirement
- Plugin version requirements

### 🔧 JSON Schema Validation

Automatic schema validation for `.falco.yaml`, `.falco.yml`, `*_rules.yaml`, and `*_rules.yml` files ensures structural correctness and validates:

- Required and optional properties for rules, macros, and lists
- Correct data types (strings, booleans, arrays, objects)
- Valid priority levels and source types
- Proper structure for exceptions and plugin version requirements
- Schema auto-synced from the official Falco repository

### 🎯 Advanced Features

- **Multi-file support**: Cross-file symbol resolution for macros and lists
- **Workspace-wide validation**: Validate all Falco files in your workspace at once
- **Exception handling**: Full support for rule exceptions with field, comparison, and value validation
- **Source-aware validation**: Field validation based on rule source type (syscall, k8s_audit, etc.)
- **Dynamic field hints**: Warnings for fields that require arguments (e.g., `proc.aname[n]`)
- **Append mode support**: Validation for rules and lists using `append: true`

---

## Installation

### From VS Code Marketplace

1. Open VS Code
2. Go to Extensions (`Ctrl+Shift+X` / `Cmd+Shift+X`)
3. Search for "Falco Rules"
4. Click **Install**

### From Command Line

```bash
code --install-extension falcosecurity.falco-rules
```

### Language Server Binary

The extension requires the `falco-lang` binary for full functionality. You can:

1. **Use the bundled binary** (included with the extension)
2. **Build from source**:
   ```bash
   cd falco-lsp
   make build
   make install  # Installs to $GOPATH/bin
   ```
3. **Download from releases**: Get pre-built binaries from [GitHub Releases](https://github.com/falcosecurity/falco-lsp/releases)

---

## Version Requirements

Falco rules files can specify version requirements to ensure compatibility:

### Engine Version

Use `required_engine_version` to specify the minimum Falco engine version:

```yaml
- required_engine_version: 0.38.0
```

This ensures that the rules file is only loaded by Falco versions >= 0.38.0.

### Plugin Versions

Use `required_plugin_versions` to specify required plugin versions:

```yaml
- required_plugin_versions:
    - name: k8saudit
      version: 0.7.0
    - name: json
      version: 0.8.0
      alternatives:
        - name: json
          version: 0.7.3
```

The extension provides:

- ✅ Auto-completion for `name`, `version`, and `alternatives` properties
- ✅ JSON Schema validation for correct structure
- ✅ Snippets for quick insertion (`engine-version`, `plugin-version`)

---

## Supported File Types

| Pattern         | Language ID  | Description                          |
| --------------- | ------------ | ------------------------------------ |
| `*.falco.yaml`  | `falco-yaml` | Falco rules in YAML format           |
| `*.falco.yml`   | `falco-yaml` | Falco rules in YAML format           |
| `*_rules.yaml`  | `falco-yaml` | Official Falco rules naming convention |
| `*_rules.yml`   | `falco-yaml` | Official Falco rules naming convention |

---

## Commands

Access commands via the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`):

| Command                                  | Description                               |
| ---------------------------------------- | ----------------------------------------- |
| `Falco: Validate Current File`           | Validate the active Falco rules file      |
| `Falco: Validate All Files in Workspace` | Validate all Falco files in the workspace |
| `Falco: Format Document`                 | Format the current document               |
| `Falco: Show Output Channel`             | Show the extension's output log           |
| `Falco: Restart Language Server`         | Restart the language server               |

---

## Configuration

Configure the extension in VS Code settings:

| Setting                     | Type    | Default | Description                                               |
| --------------------------- | ------- | ------- | --------------------------------------------------------- |
| `falco.maxNumberOfProblems` | number  | `100`   | Maximum problems to report per document                   |
| `falco.enableFormatting`    | boolean | `true`  | Enable automatic code formatting                          |
| `falco.tabSize`             | number  | `2`     | Tab size for formatting                                   |
| `falco.insertSpaces`        | boolean | `true`  | Use spaces for indentation                                |
| `falco.validateYamlFiles`   | boolean | `true`  | Validate Falco rules in YAML files                        |
| `falco.trace.server`        | string  | `"off"` | Trace server communication (`off`, `messages`, `verbose`) |

---

## Example

Here's a complete example showcasing the main features:

```yaml
# Specify minimum Falco engine version
- required_engine_version: 0.38.0

# Specify required plugin versions
- required_plugin_versions:
    - name: k8saudit
      version: 0.7.0

# Define reusable macros
- macro: container
  condition: container.id != host

- macro: spawned_process
  condition: evt.type in (execve, execveat) and evt.dir = <

# Define lists of values
- list: shell_binaries
  items: [bash, sh, zsh, ksh, csh, fish]

- list: sensitive_files
  items: [/etc/shadow, /etc/passwd, /etc/sudoers]

# Define detection rules
- rule: Shell Spawned in Container
  desc: Detect shell execution inside a container
  condition: spawned_process and container and proc.name in (shell_binaries)
  output: >
    Shell spawned in container
    (user=%user.name container=%container.name shell=%proc.name
    parent=%proc.pname cmdline=%proc.cmdline)
  priority: WARNING
  source: syscall
  tags: [container, shell, mitre_execution, T1059]

- rule: Read Sensitive File
  desc: Detect attempts to read sensitive system files
  condition: >
    evt.type in (open, openat, openat2) and
    evt.dir = < and
    fd.name in (sensitive_files) and
    not proc.name in (allowed_readers)
  output: >
    Sensitive file opened for reading
    (user=%user.name file=%fd.name process=%proc.name cmdline=%proc.cmdline)
  priority: ERROR
  source: syscall
  tags: [filesystem, security, mitre_credential_access, T1003]
  exceptions:
    - name: allowed_readers
      fields: [proc.name, fd.name]
      comps: [in, in]
      values:
        - [systemd, /etc/shadow]
```

---

## Troubleshooting

### Language Server Not Starting

1. Check the Output panel (`View > Output`) and select "Falco Rules"
2. Ensure the `falco-lang` binary is installed and accessible
3. Try restarting the language server: `Falco: Restart Language Server`

### Diagnostics Not Updating

1. Save the file to trigger a fresh validation
2. Restart the language server
3. Check for syntax errors in the Output panel

### Missing Completions

Ensure the language server is running (check the status bar for "Falco").

---

## Contributing

Contributions are welcome! Please see our [Contributing Guide](https://github.com/falcosecurity/falco-lsp/blob/main/CONTRIBUTING.md) for details.

### Development

```bash
# Clone the repository
git clone https://github.com/falcosecurity/falco-lsp.git
cd falco-lsp

# Build the Go language server
cd falco-lsp
make build

# Install extension dependencies
cd ../vscode-extension
npm install

# Build the extension
npm run build
```

---

## Resources

- [Falco Documentation](https://falco.org/docs/)
- [Falco Rules Reference](https://falco.org/docs/rules/)
- [Falco GitHub Repository](https://github.com/falcosecurity/falco)
- [Report Issues](https://github.com/falcosecurity/falco-lsp/issues)

---

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

---

<p align="center">
  Part of the <a href="https://falco.org">Falco</a> ecosystem - a <a href="https://www.cncf.io">CNCF</a> project
</p>
