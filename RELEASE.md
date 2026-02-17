# Release Process

This document describes how to create a new release for the Falco LSP project.

## Overview

The release process is automated via GitHub Actions and includes:
- Building Go binaries for multiple platforms (Linux, macOS, Windows on amd64/arm64)
- Packaging the VS Code extension (VSIX)
- Publishing to GitHub Releases
- Publishing to VS Code Marketplace
- Publishing to Open VSX Registry

## Prerequisites

### Required Permissions

- **Repository write access** - to push tags and create releases
- **VS Code Marketplace access** - `VSCE_PAT` secret must be configured with a valid Personal Access Token
- **Open VSX Registry access** - `OVSX_PAT` secret must be configured with a valid token

### Required Secrets

The following secrets must be configured in the GitHub repository:

- `VSCE_PAT` - Personal Access Token for VS Code Marketplace
- `OVSX_PAT` - Token for Open VSX Registry

## Release Steps

### 1. Prepare the Release

Before creating a release, ensure:

- [ ] All tests pass (`make test`)
- [ ] Linting passes (`make lint`)
- [ ] CHANGELOGs are updated:
  - `CHANGELOG.md` (root - for LSP/CLI changes)
  - `vscode-extension/CHANGELOG.md` (for extension changes)
- [ ] Version numbers follow [Semantic Versioning](https://semver.org/)
- [ ] Documentation is up to date

### 2. Choose the Version

Decide on the next version number following semver:

- **Patch release** (0.1.x): Bug fixes, no breaking changes
- **Minor release** (0.x.0): New features, no breaking changes
- **Major release** (x.0.0): Breaking changes

Examples: `v0.1.0`, `v0.1.1`, `v0.2.0`, `v1.0.0`

For pre-releases, use: `v0.1.0-rc.1`, `v0.2.0-beta.1`

### 3. Create and Push the Tag

```bash
# Ensure you're on main and up to date
git checkout main
git pull origin main

# Create an annotated tag
git tag -a v0.1.1 -m "Release v0.1.1"

# Push the tag to trigger the release workflow
git push origin v0.1.1
```

### 4. Automated Release Process

Once the tag is pushed, GitHub Actions will automatically:

1. **Run Tests & Linting** - Verify code quality
2. **Build Binaries** - Create falco-lang binaries for:
   - linux/amd64, linux/arm64
   - darwin/amd64, darwin/arm64
   - windows/amd64
3. **Generate Checksums** - SHA256 checksums for all binaries
4. **Package VS Code Extension** - Create `.vsix` package
5. **Create GitHub Release** - With auto-generated release notes and artifacts
6. **Publish to VS Code Marketplace** - Automatic publication (if `VSCE_PAT` is configured)
7. **Publish to Open VSX** - Automatic publication (if `OVSX_PAT` is configured)

### 5. Monitor the Release

- Check the [Actions tab](https://github.com/falcosecurity/falco-lsp/actions) for workflow status
- Verify the [GitHub Release](https://github.com/falcosecurity/falco-lsp/releases) was created
- Confirm binaries and VSIX are attached to the release
- Check the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=falcosecurity.falco-rules) for the new version
- Check [Open VSX](https://open-vsx.org/extension/falcosecurity/falco-rules) for the new version

### 6. Post-Release Tasks

After a successful release:

- [ ] Announce the release in:
  - Falco Slack (#falco channel)
  - GitHub Discussions
  - Release announcement (if major/minor release)
- [ ] Update documentation if needed
- [ ] Close related GitHub issues with milestone
- [ ] Create a new milestone for the next release

## Troubleshooting

### Release Workflow Fails

- Check the workflow logs in the Actions tab
- Common issues:
  - Test failures: Fix and push a new commit, then re-tag
  - Linting issues: Run `make lint` locally and fix
  - Build failures: Check Go version compatibility

### VS Code Marketplace Publication Fails

- Verify `VSCE_PAT` is valid and has not expired
- Check publisher ownership: `falcosecurity` must own the extension
- The workflow allows this to fail (`continue-on-error: true`) and can be published manually:

```bash
cd vscode-extension
npx @vscode/vsce publish --pat YOUR_PAT
```

### Open VSX Publication Fails

- Verify `OVSX_PAT` is valid
- Can be published manually if needed:

```bash
cd vscode-extension
npx ovsx publish --pat YOUR_PAT
```

## Manual Release (Emergency)

If automated release fails completely, you can release manually:

```bash
# Build binaries
cd falco-lsp
make build-all

# Package extension
cd ../vscode-extension
npm install
npm run build
npx @vscode/vsce package

# Create GitHub release manually and upload artifacts
gh release create v0.1.1 \
  ../falco-lsp/build/falco-lang-* \
  *.vsix \
  --title "Release v0.1.1" \
  --notes "Release notes here"

# Publish extension
npx @vscode/vsce publish --pat YOUR_VSCE_PAT
npx ovsx publish --pat YOUR_OVSX_PAT
```

## Release Checklist

- [ ] Tests pass locally (`make test`)
- [ ] Linting passes (`make lint`)
- [ ] CHANGELOGs updated (both root and vscode-extension)
- [ ] Version number decided and follows semver
- [ ] Tag created with format `vX.Y.Z`
- [ ] Tag pushed to GitHub
- [ ] GitHub Actions workflow completed successfully
- [ ] GitHub Release created with artifacts
- [ ] VS Code Marketplace updated
- [ ] Open VSX Registry updated
- [ ] Release announced in community channels
- [ ] Related issues closed

## Contact

For questions about the release process, contact the maintainers listed in the [OWNERS](./OWNERS) file.
