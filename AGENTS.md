# Repository Guidelines

## Project Structure & Module Organization

`pdf2md.mcp` is an operator-controlled PDF acquisition, conversion, and history
service. The Rust workspace includes the `pdf2md-mcp` CLI/library, its isolated
`pdf2md-convert-worker` binary, a separate `pdf2md-obscura-worker`, and
integration tests. It acquires and stores PDF bytes, then converts accepted
documents to immutable Markdown bundles with `pdf_oxide`. The library has a
caller service with anonymous RO/RW and OAuth2/OIDC modes and isolated
workspaces; the HTTP service supports acquisition and conversion jobs. There is
no MCP transport or OCR. See `docs/authentication.md` for
caller versus trusted operator boundaries and provider verification.
`README.md` owns user setup and status, `CONTRIBUTING.md` owns contributor
workflow, and `SECURITY.md` owns vulnerability reporting and disclosure. Keep
their claims aligned with executable behavior.

## Build, Test, and Development Commands

Use `CARGO_TARGET_DIR=/tmp/rust/target` and `TMPDIR=/tmp` for builds and tests.
Build the CLI and conversion worker with `cargo build --locked --package pdf2md-mcp`;
build the separate browser worker with
`cargo build --locked --package pdf2md-obscura-worker`. Format and lint with
`cargo fmt --all -- --check` and
`cargo clippy --locked --package pdf2md-mcp --all-targets -- -D warnings`;
run integration tests with `cargo test --locked --package pdf2md-mcp`. Worker
unit tests use `cargo test --locked --package pdf2md-obscura-worker`; the
browser integration script is `scripts/test-browser.sh` and requires OpenSSL.
The HTTP container smoke harness is `python3 scripts/test-http.py IMAGE`, with
optional `--minikube`. Live OIDC provider checks use
`python3 scripts/test-authelia.py`; real OIDC Kubernetes checks use
`python3 scripts/test-http-oidc.py IMAGE`. See
`examples/authelia/README.md`. Generated certificates, credentials, provider
storage, and other test state belong under `/tmp`.
The browser worker build uses the pinned upstream Obscura dependency. These
local commands do not establish hosted CI, image, MCP client, or deployment
acceptance.

Run `git status --short` to inspect changes and `git diff --check` to check
tracked edits for whitespace errors. Read new, untracked files directly;
ordinary `git diff` does not include them.

## Coding Style & Naming Conventions

`src/` contains the CLI/library, acquisition, conversion engine and worker,
policy, and storage code;
`crates/obscura-worker/` contains the separate browser worker; `tests/` contains
integration tests; `examples/` contains sample configuration. Keep conversion
rules separate from filesystem access, network access, and MCP transport.
Choose language-specific indentation, formatting, and lint rules when a
language is introduced, and commit the associated configuration.
Use Markdown headings, fenced command examples, and repository-relative paths
in root documentation.

## Testing Guidelines

Rust unit and integration tests are used; no coverage threshold exists. Add
tests alongside executable behavior, name them after the behavior verified,
and document their commands.
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
