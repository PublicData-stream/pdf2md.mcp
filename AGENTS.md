# Repository Guidelines

## Project Structure & Module Organization

`pdf2md.mcp` is intended to provide PDF-to-Markdown conversion through MCP.
The repository is in its initial documentation stage: no implementation,
source layout, assets, build manifests, or tests have been established.
`README.md` describes project status, `CONTRIBUTING.md` owns contributor
workflow, and `SECURITY.md` owns vulnerability reporting and disclosure.
Keep these documents aligned as implementation begins.

## Build, Test, and Development Commands

No build, local server, formatter, linter, or test command is configured yet.
Do not invent commands or imply that an implementation works. Add reproducible
setup and validation instructions with the first executable code.

Run `git status --short` to inspect changes and `git diff --check` to check
tracked edits for whitespace errors. Read new, untracked files directly;
ordinary `git diff` does not include them.

## Coding Style & Naming Conventions

Use descriptive names and organize modules by responsibility. Keep conversion
rules separate from filesystem access, network access, and MCP transport.
Choose language-specific indentation, formatting, and lint rules when a
language is introduced, and commit the associated configuration.
Use Markdown headings, fenced command examples, and repository-relative paths
in root documentation.

## Testing Guidelines

No framework or coverage threshold exists. Add tests alongside executable
behavior, name them after the behavior verified, and document their commands.
Prefer small synthetic PDFs and deterministic expected Markdown. Keep private
documents, credentials, and generated output out of version control. Clean up
temporary files even when tests fail where practical.

## Commit & Pull Request Guidelines

Follow `CONTRIBUTING.md`: use imperative Conventional Commits with optional
scopes, such as `docs: add contributor guidelines`. Keep changes focused.
Explain motivation, behavior changes, and validation in the PR template.
Report checks that failed or could not run; distinguish local evidence from
hosted CI or deployment results.

## Public Information & References

Follow [Public Information and References](CONTRIBUTING.md#public-information-and-references)
for public text. Prefer stable, publicly accessible sources. When none exists,
explain the necessary context inline in sanitized form. Exclude local artifacts,
session-specific aliases, secrets, personal data, and undisclosed vulnerabilities.

## Agent Instructions

Inspect current files and instructions before editing. Preserve unrelated work
and the existing `LICENSE`. Keep commit messages portable and free of local
session paths or secrets. Follow `SECURITY.md` for undisclosed vulnerabilities;
do not expose them in public issues, PRs, or commit messages.
