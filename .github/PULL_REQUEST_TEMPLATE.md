<!--  Thanks for sending a pull request! Here are some tips for you:
1. If this is your first time, please read our contributor guidelines in the https://github.com/falcosecurity/falco-lsp/blob/main/CONTRIBUTING.md file.
2. Please label this pull request according to what type of issue you are addressing.
3. Please add a release note if this PR introduces user-facing changes!
4. If the PR is unfinished while opening it, specify "wip:" in the title before the actual title, for example, "wip: my awesome feature"
-->

**What type of PR is this?**

> Uncomment one (or more) `/kind <>` lines:

> /kind bug

> /kind cleanup

> /kind documentation

> /kind feature

> /kind refactor

> /kind test

<!--
Please remove the leading whitespace before the `/kind <>` you uncommented.
-->

**Any specific area of the project related to this PR?**

> Uncomment one (or more) `/area <>` lines:

> /area lsp

> /area cli

> /area extension

> /area documentation

> /area build

<!--
Please remove the leading whitespace before the `/area <>` you uncommented.
-->

**What this PR does / why we need it**:

**Which issue(s) this PR fixes**:

<!--
Automatically closes linked issue when PR is merged.
Usage: `Fixes #<issue number>`, or `Fixes (paste link of issue)`.
-->

Fixes #

**Special notes for your reviewer**:

**Testing**:

<!-- Describe how you tested these changes. Include:
- Unit tests added/modified
- Manual testing steps
- Test coverage impact
-->

**Does this PR introduce a user-facing change?**:

<!--
If NO, just write "NONE" in the release-note block below.

If YES, a release note is required. Enter your release note in the block below.
Follow the Conventional Commits format: https://www.conventionalcommits.org/
- feat: for new features
- fix: for bug fixes
- docs: for documentation changes
- refactor: for code refactoring
- test: for test changes
- chore: for build/tooling changes

If the PR introduces breaking changes, add a line starting with "BREAKING CHANGE:"
and describe what changed and how users should migrate.

Examples:
- `feat: add go-to-definition support for macros`
- `fix: correct completion suggestions inside conditions`
- `BREAKING CHANGE: removed deprecated --legacy flag from CLI`
-->

```release-note

```

**Checklist**:

- [ ] Tests added/updated
- [ ] Documentation updated (if needed)
- [ ] Lint passes (`make lint`)
- [ ] Tests pass (`make test`)
- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
