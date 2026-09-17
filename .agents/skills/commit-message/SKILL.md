---
name: commit-message
description: Rules and guidelines for generating Git commit messages in Gatekeeper. Use when writing, formatting, or reviewing Git commit messages for this repository.
---

# Gatekeeper Commit Message Guidelines

All commit messages in Gatekeeper must follow the project's established conventions.

## Format

```text
<subsystem>: <short summary in imperative mood>

<detailed description of changes>

<optional issue references>
```

## Rules

1. **Subsystem Prefix (`<subsystem>`)**:
   - Matches the affected subsystem or directory in lowercase.
   - For modules under directories, use the path prefix (e.g. `lib/net`, `lib/fib`, `bpf`, `cps`, `debian`, `gk`, `gkctl`, `sol`).
   - For top-level files or core changes, use the file or component name (e.g. `README`, `gatekeeper`, `Makefile`, `setup.sh`).

2. **Subject Line**:
   - Format: `<subsystem>: <imperative summary>` (separated by a colon and a single space).
   - Start the summary with a lowercase letter (e.g. `lib/net: adjust dataroom based on MTU`, `README: update URLs to use HTTPS`).
   - Use the imperative mood (e.g. `add`, `fix`, `update`, `remove`, not `added`, `fixes`, `updating`).
   - Do not end the subject line with a period.
   - Keep the subject line concise (under 72 characters).

3. **Message Body**:
   - Separate the subject from the body with a blank line.
   - Wrap body text at 72 characters.
   - Focus on *what* changed and *why*, rather than *how*.
   - Mention relevant context, such as workarounds, affected dependencies, or environment conditions.

4. **Issue References**:
   - Use the project's standard closing phrase when applicable:
     `This patch closes #<issue-number>.`
