# pdf2md.mcp

`pdf2md.mcp` is an operator-controlled PDF acquisition and history service
written in Rust. It can retrieve configured public HTTPS sources, acquire
through a pinned Obscura browser worker, or import local PDFs. It records
attempt history and keeps accepted PDF bytes as immutable, content-addressed
objects.

## Project Status

The current executable implements acquisition, header-only PDF validation,
content-addressed storage, and history. It does not parse PDF content, convert
PDFs to Markdown, or expose an MCP server yet. The repository has no supported
release policy.

## Requirements

- Rust 1.88 or newer (edition 2024); local validation uses Rust 1.99.1.
- Linux for the Obscura worker and its process memory monitoring. Direct HTTPS
  acquisition and storage also target the supported Linux deployment.
- The `pdf2md-obscura-worker` binary when a source uses `obscura` or `browser`
  acquisition. Direct HTTPS and manual-file workflows do not require it.
- Optional PostgreSQL 18 or newer when selecting an external metadata database.
- Browser builds need native C/C++ tooling. On Debian/Ubuntu, install
  `build-essential clang cmake libclang-dev libssl-dev llvm-dev ninja-build
  pkg-config python3`. OpenSSL is also required for browser integration tests.

## Build and Run

Build the default CLI and, when `obscura` or `browser` acquisition is needed,
its separate worker from the repository root:

```sh
export CARGO_TARGET_DIR=/tmp/rust/target
export TMPDIR=/tmp
cargo build --locked --release --package pdf2md-mcp
cargo build --locked --release --package pdf2md-obscura-worker
export PATH="$CARGO_TARGET_DIR/release:$PATH"
```

The CLI stores data under `pdf2md-mcp-data/` by default. Set `--data-dir` to
choose another storage root, and `--config` to load an optional TOML source
configuration. The daemon starts only with the explicit `run` subcommand:

```sh
export CARGO_TARGET_DIR=/tmp/rust/target
export TMPDIR=/tmp
cargo run -- --data-dir ./pdf2md-mcp-data --config ./examples/sources.toml status
cargo run -- --data-dir ./pdf2md-mcp-data --config ./examples/sources.toml fetch public-notice
cargo run -- --data-dir ./pdf2md-mcp-data --config ./examples/sources.toml fetch --all
cargo run -- --data-dir ./pdf2md-mcp-data --config ./examples/sources.toml history
cargo run -- --data-dir ./pdf2md-mcp-data --config ./examples/sources.toml run
```

`fetch SOURCE [SOURCE ...]` performs a fetch operation for the selected
configured sources; `fetch --all` selects every source in the config.
`fetch-url URL` performs a fetch operation for a URL, with `--mode https` or
`--mode obscura`. `scan` imports local PDFs currently in the `pdfs/` directory
under the data root and exits with an error if any candidate fails; `watch`
repeats that manual scan. `run` watches `pdfs/` and polls remote sources only
when they have an `interval_secs` value. `status` shows the latest
observation for each source, and `history [SOURCE]` shows all recorded
attempts, optionally filtered by source ID. These read-only commands can run
while the daemon owns the data root; they require that the data root already
exists. `--json` selects JSON output. Use `--help` for current options.

Put manually supplied PDFs under `<data-dir>/pdfs/`. The importer waits two
seconds before reading a candidate, checks that it did not change, and does
not follow symbolic links. Accepted bytes are stored under
`<data-dir>/objects/` using their SHA-256 digest as the filename and are
published without replacing an existing object. Metadata and acquisition
history live in SQLite in the same storage root by default. PostgreSQL stores
metadata only, while PDF objects remain in the storage root; take a coordinated
backup of both when using PostgreSQL.

Only one process may own writes to a data root at a time. `fetch`, `fetch-url`,
`scan`, `watch`, and `run` write history; while `watch` or `run` owns the root,
use only `status` and `history` from another process.

## Configuration

See [`examples/sources.toml`](examples/sources.toml) for a schema example. Set
the environment variables referenced by a source before fetching it. The
optional `[limits]` section sets aggregate size, timeout,
concurrency, and browser-worker memory limits. Each `[[sources]]` entry has a
stable unique `id`, acquisition `mode`, and starting `url`. Remote polling is
disabled unless `interval_secs` is set.

Modes are `https`, `obscura`, and `browser`. Both `obscura` and `browser` use
the separate worker; `browser` additionally supports configured navigation
steps. HTTPS custom headers are scoped to an explicitly listed origin. Browser
cookies and form values can be supplied from environment variables or files;
referenced files and browser script files are resolved relative to the TOML
file. Avoid literal credentials in config. The origin in `url` is permitted
automatically; list any additional public HTTPS origins in `allowed_origins`.
Browser sources require a response URL glob that matches the intended PDF
response.

The database setting names an environment variable; it does not read
`DATABASE_URL` implicitly. Set `database_url_env` in the TOML file or pass
`--database-url-env NAME` (which overrides the configured variable name). If
neither is set, the service uses its local SQLite metadata database. External
metadata storage supports PostgreSQL 18 or newer.

Default limits are 512 MiB per document, 20 minutes per operation, and one
concurrent acquisition. Source limits may override the byte and time values;
`[limits]` controls the shared defaults, concurrency, and worker RSS threshold.
The service makes up to three tries per operation in the same acquisition
mode, using a short backoff with jitter and honoring a valid upstream
`Retry-After` value. Browser selector and PDF wait steps default to 30 seconds;
Obscura stealth requests have a 30-second timeout. Obscura document navigation
has a 64 MiB response cap. Browser responses are
buffered before publication, so the per-document byte limit does not bound
process memory. Worker RSS is sampled every 250 ms against a configurable
threshold (4 GiB by default); this is monitoring and termination, not a hard
operating-system memory limit.

For the default resource settings, allow at least 6 GiB of memory for the
container. The per-source deadline is checked during staging and before the
metadata commit. A database commit already in progress can finish, and a
running filesystem call cannot be preempted. With the default concurrency of
one, manual inbox work can
wait behind a running remote acquisition; `run` scans the inbox before its
next remote admission window and again at least every 30 seconds while idle.

Run the core formatter, linter, and tests from the repository root:

```sh
export CARGO_TARGET_DIR=/tmp/rust/target
export TMPDIR=/tmp
cargo fmt --all -- --check
cargo clippy --locked --package pdf2md-mcp --all-targets -- -D warnings
cargo test --locked --package pdf2md-mcp
cargo test --locked --package pdf2md-obscura-worker
scripts/test-browser.sh
```

For complete native lint coverage, run
`cargo clippy --locked --workspace --all-targets -- -D warnings`.

For larger or slower browser cases, set `RUN_LARGE_PDF_TESTS=1` for the 512 MiB
boundary fixture or `RUN_SLOW_BROWSER_TESTS=1` for the upstream 30-second
timeout fixture when invoking `scripts/test-browser.sh`.
The direct HTTPS 512 MiB boundary check runs with
`cargo test --locked --package pdf2md-mcp --lib direct_default_512_mib_boundary -- --ignored`.

PostgreSQL integration cases skip their PostgreSQL path when
`PDF2MD_TEST_POSTGRES_URL` is unset; set it to a PostgreSQL 18+ URL to exercise
external database paths. Other storage tests use SQLite. The
browser end-to-end cases are ignored in the default test run; the script builds
the worker and uses local TLS fixtures and OpenSSL to run them.
## Security and Limitations

PDF input and remote responses are untrusted. Downloads are subject to byte and
time limits, HTTPS source policies, and stable-file checks for manual imports.
Acquisition only checks for a PDF signature within the first 1024 bytes; it
does not fully parse or sanitize PDF content. The browser worker runs as a
separate process, but this implementation does not provide an operating-system
sandbox or hard memory limit. Browser egress is routed through an application
proxy that restricts HTTPS port 443 to configured public origins. URLs recorded
in history retain only the scheme and origin; credentials, paths, query strings,
and fragments are removed.
Do not give the service access to credentials or documents beyond its intended
scope.

Browser workflows support original HTTPS responses in one page/session. Blob
downloads, popups, CAPTCHA, and interactive MFA are unsupported. If Obscura
rejects a fetch/XHR body before its response callback, `pdf_not_found` may also
mean an upstream size rejection; raw downloads expose a distinct size error.

No MCP transport, PDF-to-Markdown conversion engine, release support window, or
end-to-end client acceptance is currently provided. See the
[Security Policy](SECURITY.md) for vulnerability reporting.

## Repository Contents

- [Repository Guidelines](AGENTS.md): orientation and instructions for agents.
- [Contributing](CONTRIBUTING.md): workflow, style, validation, commits, and PRs.
- [Security Policy](SECURITY.md): private vulnerability reporting and disclosure.
- [Third-party notices](THIRD_PARTY_NOTICES.md): notices for included upstream code.
- [Example source configuration](examples/sources.toml): source and limit settings.
- [Pull request template](.github/pull_request_template.md): change and validation
  information for reviewers.
- [License](LICENSE): GNU Affero General Public License, version 3.

## Contributing

Read `CONTRIBUTING.md` before making changes. Keep contributions focused and
report the validation actually performed. Language and tooling decisions should
be documented when introduced rather than assumed from another repository.
