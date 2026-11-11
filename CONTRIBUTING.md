# Contributing to pdf2md.mcp

`pdf2md.mcp` is intended to provide PDF-to-Markdown conversion through MCP.
The repository currently contains documentation and a license; no implementation
language, runtime architecture, build system, or test framework has been chosen.
This document is the source of truth for contributor workflow. See
[Repository Guidelines](AGENTS.md) for agent orientation and the
[Security Policy](SECURITY.md) for vulnerability reporting.

## Contribution Workflow

1. Inspect the current repository and identify the behavior or documentation
   being changed. Explain significant design choices in the PR.
2. Make a focused change. Preserve unrelated work and avoid incidental cleanup.
3. Add regression tests for new or changed executable behavior.
4. Update documentation when setup, commands, configuration, or public behavior
   changes.
5. Run relevant checks and report their actual results, including failures and
   checks that could not run.
6. Remove temporary files and resources created during validation.

Use repository-relative paths in root documentation and command examples.
Run commands from the repository root unless an example states otherwise.

## Project Structure and Coding Style

The source, tests, and fixture directories are not established yet. Document
their locations in `README.md` when introducing them, and keep generated output
separate from source contributions.

Organize modules around clear responsibilities. Keep conversion rules separate
from filesystem, network, and MCP transport operations. Use descriptive names
and avoid generic utility modules without a clear shared responsibility.

When introducing a language, include formatter and lint configuration and
document the indentation and naming conventions those tools enforce. Do not
introduce competing styles. Use Markdown headings, fenced examples, and inline
code for filenames, commands, and identifiers.

## Development and Validation

There are currently no build, run, lint, or test commands. Add reproducible
setup instructions, prerequisites, and validation commands alongside the first
executable implementation. Do not copy commands from another project without
verifying that they apply here.

For documentation changes, inspect the complete changed text and check links
and anchors. These Git commands help review the working tree:

```sh
git status --short
git diff --check
git diff
```

The diff commands do not inspect new, untracked files. Review those files
directly before staging. Do not describe local checks as hosted CI, deployment,
or end-to-end MCP client verification.

## Testing and Fixtures

No test framework or coverage threshold is established. Test names should
describe observable behavior. Cover successful conversion and relevant failure
cases when executable behavior is added; avoid tests that merely mirror
implementation details.

Prefer small synthetic PDFs with deterministic expected Markdown. Include
fixture provenance or generation instructions when needed. Use documents that
can be redistributed, and never commit private documents, credentials, logs,
or incidental generated output. Generate disposable test data in temporary
directories and clean up after failures where practical.

## Commit Messages

New contributions use lightweight Conventional Commits:

```text
<type>[optional scope]: <imperative summary>
```

Use `feat`, `fix`, `docs`, `tests`, `refactor`, `perf`, `security`, `ci`, or
`chore` as the type. Choose a scope only when it clarifies the affected area.

```text
docs: add contributor guidelines
fix(conversion): preserve table order
tests: cover malformed PDF input
```

This is a new contribution policy; the initial commit predates it. Keep each
commit focused. Messages should be understandable outside the development
session: omit absolute host paths, local aliases, secrets, and private evidence.

## Public Information and References

Public documentation, commit messages, issues, and pull requests must contain
portable, repository-relevant context that readers can understand without
access to the author's development session.

- Prefer stable, publicly accessible references: tracked repository files,
  public GitHub projects, issues, pull requests, commits, published security
  advisories, and official documentation. Link to the relevant section; use an
  exact revision or version when it matters to the claim.
- Do not cite absolute host paths, session-specific command aliases, temporary
  artifacts, private logs, or inaccessible local material. Describe the
  reproducible command and relevant result instead. For example, write
  "conversion regression tests passed" rather than referring to a temporary
  log file or a local command alias.
- If no suitable public source exists, explain the necessary context inline
  in sanitized form. State the evidence and its limits, distinguish observed
  results from inference, and do not imply independent public verification.
- Remove secrets, personal data, sensitive document content, private URLs, and
  undisclosed vulnerability details before sharing text, logs, screenshots, or
  attachments. A need for a reference does not permit disclosing private data;
  follow [SECURITY.md](SECURITY.md) for undisclosed security reports.

Local evidence may inform a change, but the public explanation must stand on
its own. Reference only material that supports the associated claim; do not
present planned, unavailable, or unexecuted checks as completed validation.

## Pull Requests

Use the PR template to explain the change, motivation, and relevant issue.
List validation commands and outcomes; state why a check was unavailable.
Describe compatibility effects when interfaces or configuration exist and
change. Include screenshots only for visual changes.

Review untrusted-document handling, resource consumption, external access, and
output handling when relevant to the change. Report undisclosed vulnerabilities
through `SECURITY.md`, not through public PR text. Preserve `LICENSE` and
document any third-party code or fixture licensing introduced by a contribution.
