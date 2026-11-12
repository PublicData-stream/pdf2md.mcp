# Contributing to pdf2md.mcp

`pdf2md.mcp` is an operator-controlled PDF acquisition, conversion, and history
service. The Rust 2024 workspace contains a CLI/library, a separate browser
worker, a conversion worker binary, and integration tests. `pdf_oxide` converts
accepted PDFs into immutable Markdown bundles. A transport-independent caller
service supports anonymous RO/RW and OAuth2/OIDC authentication with isolated
workspaces and supports HTTP acquisition and conversion jobs. The project has
an opt-in Streamable HTTP MCP endpoint with eight read-only tools and no OCR.
See [MCP tools](docs/mcp.md) for contracts and compatibility. This document is the source of truth for contributor
workflow. See
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

The main CLI and library are under `src/`, the browser worker is under
`crates/obscura-worker/`, integration tests are under `tests/`, and example
configuration is under `examples/`. Keep generated output separate from source
contributions.

Organize modules around clear responsibilities. Keep conversion rules separate
from filesystem, network, and MCP transport operations. Use descriptive names
and avoid generic utility modules without a clear shared responsibility.

When introducing a language, include formatter and lint configuration and
document the indentation and naming conventions those tools enforce. Do not
introduce competing styles. Use Markdown headings, fenced examples, and inline
code for filenames, commands, and identifiers.

## Development and Validation

Use Rust 1.88 or newer and install ripgrep (`rg`) on `PATH` for the core and
MCP search tests (for example, `sudo apt-get install ripgrep` on Ubuntu).
From the repository root, build the CLI and its
conversion worker together, and build the separate browser worker with:

```sh
export CARGO_TARGET_DIR=/tmp/rust/target
export TMPDIR=/tmp
cargo build --locked --package pdf2md-mcp
cargo build --locked --package pdf2md-obscura-worker
```

Run `cargo fmt --all -- --check`,
`cargo clippy --locked --package pdf2md-mcp --all-targets -- -D warnings`, and
`cargo test --locked --package pdf2md-mcp` for the core checks. Run worker unit
tests with `cargo test --locked --package pdf2md-obscura-worker`; run local
browser integration checks with `scripts/test-browser.sh` (requires OpenSSL).
The worker build fetches the exact upstream Obscura revision pinned in its
manifest. PostgreSQL integration cases use `PDF2MD_TEST_POSTGRES_URL` when set
and otherwise skip their PostgreSQL path. The destructive conversion migration
test uses a separate `PDF2MD_TEST_CONVERSION_POSTGRES_URL` pointed at a disposable
database; never set it to an existing application database. Run it with
`cargo test --locked --package pdf2md-mcp --test conversion_storage postgres_migration_bundle_export_and_namespace_isolation -- --test-threads=1`.
Report network or toolchain blockers
as such; do not imply checks passed when they were not run. These commands do
not establish hosted CI, container, MCP-client, or deployment acceptance.

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

Authentication, caller-boundary, and workspace tests are part of the core test
suite. For real-provider acceptance, run `python3 scripts/test-authelia.py`
with Docker, OpenSSL, and Python 3 available. See
[the Authelia harness guide](examples/authelia/README.md). The harness uses
disposable state under `/tmp`; keep live tokens and provider credentials out
of logs and version control. This harness covers the library and HTTP boundaries;
it does not establish MCP client or Kubernetes deployment acceptance.
The container HTTP smoke test is `python3 scripts/test-http.py IMAGE`; add
`--minikube` for its disposable Kubernetes path. The real-provider Kubernetes
harness is `python3 scripts/test-http-oidc.py IMAGE`. See the script prerequisites.

The bundled API console uses browser JavaScript, HTML, and CSS with two-space
indentation and LF endings (`.editorconfig`). Its JavaScript lint rules are in
`eslint.config.mjs`. Run the pinned development lint without installing runtime
Node dependencies into the repository:

```sh
npm_config_cache=/tmp/pdf2md-http-npm-cache npx --yes --package eslint@10.14.0 eslint src/http/docs.js eslint.config.mjs
```

The Rust service embeds the console assets; Node is required only for this
optional contributor lint command.

### CI coverage and reproduction

`.github/workflows/check.yml` runs native AMD64 and ARM64 checks on Ubuntu
24.04. It preserves the existing AMD64 core check name and adds a stable
`CI summary` covering every selected job group. Selecting that summary in
repository protection settings is a separate operator action.

Each push and pull request runs workflow/pin checks, API-console lint, Rust
formatting and workspace Clippy, core PostgreSQL tests, an isolated destructive
conversion migration, worker unit tests, browser integration, full Authelia
acceptance, Docker CLI/conversion/HTTP/MCP tests, and separate
conversion/HTTP/OIDC Minikube harnesses. Native executables and images are built
once per architecture and shared within the run. Consumers verify commit,
architecture and checksums. Image configuration IDs identify local images;
they are not published registry digests or independent provenance.

Rust-enabled CI jobs install Ubuntu's ripgrep package and verify its version
and a real stdin search before compilation. Missing or unusable ripgrep fails
dependency setup; MCP HTTP tests exercise search without skipping it.

Daily runs at 03:17 UTC also run large/slow browser cases and live RFC
acquisition through OIDC Kubernetes. Manual dispatch includes these only when
`extended_tests` is enabled. Only superseded PR runs are cancelled. Matrix
failures do not cancel other lanes, and the summary rejects failed, cancelled
or unexpectedly skipped required groups.

CI uses a dedicated rootless Docker daemon with storage under `/tmp`, Minikube
1.39.0, Kubernetes 1.37.0 and containerd. Local harnesses require the same
rootless Docker storage boundary and create fresh profiles. Keep credentials,
certificates, Docker volumes, caches, kubeconfigs and test outputs under `/tmp`.
Before starting Docker, CI starts the runner's user manager and D-Bus socket,
checks delegated CPU, memory and process controllers, and exports the verified
user bus address. The setup action keeps its own daemon runtime under `/tmp`;
the explicit bus address connects containerd/runc to the user manager despite
that runtime-directory override. The host's existing systemd/D-Bus facilities
remain host-managed.

The Docker readiness probe starts a networkless container from the pinned
PostgreSQL catalog image with an overridden shell entrypoint. It checks the
effective cgroup CPU quota, memory ceiling and process limit, then removes the
container. Metadata checks alone do not establish container readiness. Fixed
probe/cleanup status codes are retained in diagnostics, including failed image
build jobs. Cleanup failures fail an otherwise successful lane and remain
visible alongside an existing failure.

Required OIDC checks use a synthetic HTTPS PDF in the disposable Pod. A
test-only `NET_ADMIN` init container configures and verifies a Pod-local
loopback route before the API starts. The fixture sidecar uses a trusted test
CA; the API retains its normal UID, TLS checks and public-address policy.
This is test scaffolding, not a deployment example. The harness's default
source remains the public RFC.

Run helper checks and export the image catalog from the repository root:

```sh
export CARGO_TARGET_DIR=/tmp/rust/target TMPDIR=/tmp PYTHONDONTWRITEBYTECODE=1
actionlint
python3 scripts/ci/check.py source
python3 -m unittest discover -s tests/scripts -p 'test_*.py'
docker compose -f scripts/ci/compose.yml config --format json > /tmp/pdf2md-ci-images.json
python3 scripts/ci/check.py images --compose-json /tmp/pdf2md-ci-images.json > /tmp/pdf2md-ci-images.env
set -a
. /tmp/pdf2md-ci-images.env
set +a
export PDF2MD_TEST_KUBERNETES_VERSION=v1.37.0
```

Build the runtime and fixture images in the selected rootless daemon:

```sh
docker build --provenance=false --tag pdf2md-mcp:ci-local .
docker build --provenance=false --tag pdf2md-fixture:ci-local scripts/ci/fixture
export CI_IMAGE=pdf2md-mcp:ci-local PDF2MD_FIXTURE_IMAGE=pdf2md-fixture:ci-local
```

Run `bash scripts/ci/run.sh LANE`
with any of: `core-postgres`, `cli`, `conversion`, `http`, `browser`, `authelia`,
`k8s-conversion`, `k8s-http`, `k8s-oidc`, `browser-extended`, or `oidc-live`.
The CLI lane also tests PostgreSQL. The core lane creates separate empty
databases for ordinary tests and the destructive migration; never substitute
an application database.

Browser and provider harnesses accept verified prebuilt executables through
`PDF2MD_BROWSER_TEST_EXECUTABLE` and `PDF2MD_LIVE_AUTHELIA_TEST_EXECUTABLE`.
`PDF2MD_TEST_WORKER` selects the browser worker. Omit these settings to use the
existing Cargo build paths. Required CI invokes
`python3 scripts/test-http-oidc.py IMAGE --source-mode fixture`; `--source-mode live`
retains external-source acceptance.

External actions use full commit SHAs with version comments. Container images
use digests; the shared test-image catalog is `scripts/ci/compose.yml`.
Rust-enabled CI jobs use the official rustup and executable proxies already
provided by the Ubuntu AMD64 and ARM64 runners. `scripts/ci/setup-rust.sh`
installs Rust 1.99.1 with the minimal profile plus Clippy and rustfmt into the
isolated `/tmp/pdf2md-ci/rustup` home, without updating rustup itself. Cargo state
stays in `/tmp/pdf2md-ci/cargo`. The helper verifies the compiler version,
isolated sysroot and component commands, then selects the runner proxies and
exact toolchain for subsequent steps. Missing runner tools or failed checks
fail setup; jobs with `rust: 'false'` do not invoke it. Local development still
accepts Rust 1.88 or newer; there is no repository toolchain override.

For focused Rust setup validation, run `bash -n scripts/ci/setup-rust.sh`,
`actionlint`, `python3 scripts/ci/check.py source` and the Python helper tests
shown above. The setup tests use disposable state under `/tmp` and stub commands
to cover installation failures, tool selection and step environment propagation.
To check an actual installation, run the helper with fresh `CARGO_HOME`,
`RUSTUP_HOME`, `GITHUB_ENV` and `GITHUB_PATH` paths under `/tmp`,
`CARGO_TARGET_DIR=/tmp/rust/target` and `TMPDIR=/tmp`. Apply its environment and
path files in a fresh shell, verify `cargo --version`, `rustc --version`,
`cargo fmt --version` and `cargo clippy --version`, and compile a synthetic
Rust program under `/tmp`. Remove the disposable setup state afterwards.

For focused Docker setup validation, run `bash -n scripts/ci/setup-docker-session.sh`,
`actionlint`, `python3 scripts/ci/check.py source` and the Python helper tests
above. The offline tests cover user-session failures, environment propagation,
missing delegation, rejected daemon metadata, ignored limits and cleanup,
including interruption. On a Linux host with a user systemd manager and the
required delegated controllers, run the session helper with `GITHUB_ENV` set
to a disposable file under `/tmp`. It enables lingering for the current user
and starts the user manager and D-Bus socket; it does not restart existing
Docker services. Apply the exported bus address before starting a separate
rootless daemon. After exporting the pinned image catalog, run
`python3 scripts/ci/verify-docker.py`. Run live daemon checks only with Docker
storage under `/tmp`; remove any daemon, builder and smoke-test resources you
create. A passing readiness probe does not establish BuildKit, complete image
builds, Kubernetes, native ARM64 or hosted Actions acceptance.

Dependabot opens weekly action, Docker/Compose and Cargo update PRs without
automatic merging. Coordinate Rust image/toolchain changes with documented
versions. Installer versions/checksums in `scripts/ci/install-tools.sh` receive
manual review. Native jobs and image builds limit Cargo/CMake parallelism to
two; the Dockerfile exposes these as build arguments for local overrides.
Artifacts expire after seven days; rerun the complete workflow
when a downstream rerun's build artifacts have expired. Diagnostics contain
allowlisted status information, never credentials or raw provider configuration.

Local AMD64 results do not establish native ARM64, hosted Actions, registry
publication, deployment, or acceptance by an external MCP client.

## Testing and Fixtures

Rust unit and integration tests are the project's executable verification
layer; no coverage threshold is set. Keep test names specific to the behavior
verified and add cases alongside executable changes. Report the checks actually
run; an acquisition check does not establish conversion behavior.

Prefer small synthetic PDFs with deterministic expected Markdown. Include
fixture provenance or generation instructions when needed. Conversion runs in
the `pdf2md-convert-worker` process; keep parsing separate from filesystem and
network access. Test page selection, explicit retries, worker limits, immutable
bundle publication and history migration with disposable fixtures. Use
documents that can be redistributed, and never commit private documents,
credentials, logs, or incidental generated output. Generate disposable test
data in temporary directories and clean up after failures where practical.

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
