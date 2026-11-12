# pdf2md.mcp

`pdf2md.mcp` is an operator-controlled PDF acquisition and history service
written in Rust. It can retrieve configured public HTTPS sources, acquire
through a pinned Obscura browser worker, or import local PDFs. It records
attempt history and keeps accepted PDF bytes as immutable, content-addressed
objects.

## Project Status

The executable implements acquisition, header-only PDF validation,
content-addressed storage, conversion through `pdf_oxide`, immutable conversion
bundles, and acquisition/conversion history. Automatic conversion is enabled
by default: foreground acquisition commands process accepted documents, and
the background `watch`/`run` daemon processes pending conversions. The trusted CLI can
also request conversions, retry them, select pages, inspect history, and export
verified bundles. The HTTP service provides isolated caller workspaces with
`none_ro`, `none_rw`,
and OIDC-backed `oauth2` modes; see [authentication](docs/authentication.md)
and the [HTTP API](docs/http-api.md). An opt-in MCP endpoint exposes eight read-only retrieval and search tools;
see [MCP tools](docs/mcp.md). There is no OCR. The
repository has no supported release policy.

## Requirements

- Rust 1.88 or newer (edition 2024); CI and the container build use Rust 1.99.1.
- Linux for the Obscura worker and its process memory monitoring. Direct HTTPS
  acquisition and storage also target the supported Linux deployment.
- The `pdf2md-obscura-worker` binary when a source uses `obscura` or `browser`
  acquisition. Direct HTTPS and manual-file workflows do not require it.
- Optional PostgreSQL 18 or newer when selecting an external metadata database.
- Browser builds need native C/C++ tooling. On Debian/Ubuntu, install
  `build-essential clang cmake libclang-dev libssl-dev llvm-dev ninja-build
  pkg-config python3`. OpenSSL is also required for browser integration tests.

## Build and Run

See [CI coverage and reproduction](CONTRIBUTING.md#ci-coverage-and-reproduction)
for the native architecture matrix and local Docker, Minikube, and provider checks.

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

`run` also processes accepted documents' pending automatic conversions. To
request or inspect conversions directly, use the trusted CLI:

```sh
pdf2md-mcp --data-dir ./pdf2md-mcp-data convert DOCUMENT_ID
pdf2md-mcp --data-dir ./pdf2md-mcp-data convert DOCUMENT_ID --pages 1-3,7
pdf2md-mcp --data-dir ./pdf2md-mcp-data convert DOCUMENT_ID --force
pdf2md-mcp --data-dir ./pdf2md-mcp-data conversion-history
pdf2md-mcp --data-dir ./pdf2md-mcp-data conversion-history DOCUMENT_ID
pdf2md-mcp --data-dir ./pdf2md-mcp-data export CONVERSION_ID --output ./bundle
```

Page numbers are 1-based; page ranges are normalized to ascending unique page
numbers. A matching successful conversion is reused unless `--force` requests
a new attempt. Conversion output is published as an immutable bundle containing
`document.md`, any extracted page images, and a manifest. Export verifies the
stored bundle and writes to a new directory without replacing existing files.
The core package build produces both the CLI and `pdf2md-convert-worker`.
The default worker executable is `pdf2md-convert-worker`; use
`--conversion-worker` to select another executable path. The `run` daemon sends
automatic conversion progress and errors to stderr, keeping acquisition stdout
machine-readable; explicit conversion commands print their result to stdout.

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
metadata only, while PDF objects and conversion bundles remain in the storage
root; take a coordinated backup of both when using PostgreSQL. Bundles live
under `conversions/`, addressed by their manifest digest. Successful bundles and
attempt history are retained across retries; recovery removes unpublished
staging and orphan bundles.

For manual loading, initialize the directories once, copy a PDF, and scan:

```sh
pdf2md-mcp --data-dir ./pdf2md-mcp-data scan
cp ./document.pdf ./pdf2md-mcp-data/pdfs/
pdf2md-mcp --data-dir ./pdf2md-mcp-data scan
```

Run `pdf2md-mcp --data-dir ./pdf2md-mcp-data watch` in another terminal to
register copied files automatically. For a one-off HTTPS download, use
`pdf2md-mcp fetch-url https://www.rfc-editor.org/rfc/rfc9110.pdf`;
add `--mode obscura` to use the browser-like transport.

Only one process may own writes to an individual workspace root at a time.
The commands above select the operator workspace by default. `fetch`, `fetch-url`,
`scan`, `watch`, `run`, and `convert` write history. Stop the daemon before
explicit conversion. While it owns the root, `status`, `history`,
`conversion-history`, and `export` remain available from another process.

## Configuration

The CLI remains a trusted operator interface and defaults to the original private
operator workspace. Start the HTTP service explicitly:

```sh
pdf2md-mcp --data-dir ./pdf2md-mcp-data --config ./examples/http.toml serve
curl http://127.0.0.1:8080/healthz
```

It binds to `127.0.0.1:8080` by default. `--listen` overrides the bind address.
Caller mode defaults to `none_ro`; `none_rw` permits shared writes, and OAuth2
uses per-user workspaces and scopes. See the [HTTP API guide](docs/http-api.md),
[authentication guide](docs/authentication.md), and
[Kubernetes example](examples/kubernetes/README.md).

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

Automatic conversion is enabled by default. The defaults are one concurrent
conversion per workspace, a 1 GiB input and output budget per conversion,
25,000 pages, a one-hour timeout, an 8 GiB address-space limit, and a 32-million
pixel image limit. The worker also caps assets at 100,000. These are conversion
limits; acquisition has its own byte and time limits. The Obscura browser path
has upstream response limits (including a 64 MiB navigation cap), so a 1 GiB
conversion input limit does not mean every acquisition mode can retrieve a
document that large. The converter does not perform OCR, and it does not
provide an operating-system sandbox. For example, disable conversion in config
with:

```toml
[conversion]
enabled = false
```

Automatic requests are committed with acquisition and deduplicated per PDF in
each workspace. Pending requests resume when `watch` or `run` restarts; failed,
cancelled, or interrupted attempts require explicit `convert`. There is no
automatic backfill of existing history. An automatic parsing failure preserves
the PDF and successful acquisition exit status, with a separate stderr summary.

The database setting names an environment variable; it does not read
`DATABASE_URL` implicitly. Set `database_url_env` in the TOML file or pass
`--database-url-env NAME` (which overrides the configured variable name). If
neither is set, the service uses its local SQLite metadata database. External
metadata storage supports PostgreSQL 18 or newer.

Default limits are 1 GiB per document, 20 minutes per operation, and one
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

The browser worker's default RSS threshold is 4 GiB; PDF conversion separately
has an 8 GiB address-space ceiling. These are configured limits, not measured
peak memory or a container sizing benchmark. The per-source deadline is checked
during staging and before the metadata commit. A database commit already in
progress can finish, and a running filesystem call cannot be preempted. With
the default acquisition concurrency of one, manual inbox work can wait behind a
running remote acquisition; `run` scans the inbox before its next remote
admission window and again at least every 30 seconds while idle.

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
The direct HTTPS 1 GiB boundary check runs with
`cargo test --locked --package pdf2md-mcp --lib direct_default_1024_mib_boundary -- --ignored`.

PostgreSQL integration cases skip their PostgreSQL path when
`PDF2MD_TEST_POSTGRES_URL` is unset; set it to a PostgreSQL 18+ URL to exercise
external database paths. Other storage tests use SQLite. The
browser end-to-end cases are ignored in the default test run; the script builds
the worker and uses local TLS fixtures and OpenSSL to run them. The CI workflow
runs formatting, core lint, and core tests;
it does not build the browser worker or Docker image.
## Container

Build an image containing the CLI, conversion worker, and browser worker:

```sh
docker build -t pdf2md-mcp .
```

The image runs as an unprivileged user, uses `/data` for durable storage, and
starts the daemon with `run`. Mount a persistent volume at `/data`. The
conversion worker is used by the CLI and daemon for PDF parsing. The browser
worker is included and used only for `obscura` or `browser` sources. The image
does not include or manage PostgreSQL. If a build environment intercepts HTTPS, provide
its trusted CA to BuildKit without copying it into an image layer:

```sh
docker build --secret id=proxy_ca,src="$PROXY_CA_FILE" -t pdf2md-mcp .
```

To run with a local configuration file, mount it read-only and mount a
persistent data volume. For the sample source, inject its environment values
through your runtime secret mechanism before requesting those sources:

```sh
docker run --rm \
  --mount type=volume,src=pdf2md-data,dst=/data \
  --mount "type=bind,src=$PWD/sources.toml,dst=/etc/pdf2md/sources.toml,readonly" \
  --env PDF2MD_NOTICE_TOKEN \
  --env PDF2MD_BROWSER_SESSION \
  --env PDF2MD_SEARCH_TERM \
  pdf2md-mcp --data-dir /data --config /etc/pdf2md/sources.toml run
```

After building the CLI and image, validate manual loading, revision history,
watching, concurrent status reads, shutdown, and restart persistence with:

```sh
cargo build --locked --package pdf2md-mcp
python3 scripts/test-cli-docker.py pdf2md-mcp
```

After building the image, the conversion harness can exercise conversion in
the image:

```sh
python3 scripts/test-conversion.py pdf2md-mcp --minikube
```

The harness requires the Docker daemon's data root to be under `/tmp` and checks
that prerequisite before creating disposable state.

Set `PDF2MD_TEST_POSTGRES_URL` to include local CLI PostgreSQL checks. The harness
uses disposable bind mounts under `/tmp`, checks the image's default user, and
adapts the longer bind-mount test to rootless Docker's UID mapping. It does not
test a production deployment.

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

Conversion parses untrusted PDF content in a separate worker process with
configured resource limits. Process limits and supervision reduce exposure but
are not an operating-system sandbox. Markdown includes embedded text, inferred
headings/lists/links and best-effort tables; PNG references follow each page's
text rather than reproducing visual placement. Surfaced page or image errors
fail the whole attempt, but upstream parsing can silently omit content, so
success does not guarantee complete extraction. Image-only pages yield images
and a no-text warning. Password-required PDFs fail distinctly; no password
input is supported. Chained JPEG filters and JPEG 2000 images are unsupported
in this profile; an unreadable image fails the attempt. Generated Markdown
remains untrusted content.

Library callers must cancel through the cancellation token and await conversion
to guarantee worker reaping. Dropping a worker future kills its process group,
with reaping delegated to Tokio. Output quotas bound staged bytes; transient
parser/encoder allocations are governed separately by the address-space limit.
The project has no OCR or supported-release window. External client UI
acceptance remains unverified. See the
[Security Policy](SECURITY.md) for vulnerability reporting.

## Repository Contents

- [Repository Guidelines](AGENTS.md): orientation and instructions for agents.
- [Contributing](CONTRIBUTING.md): workflow, style, validation, commits, and PRs.
- [Security Policy](SECURITY.md): private vulnerability reporting and disclosure.
- [Third-party notices](THIRD_PARTY_NOTICES.md): notices for included upstream code.
- [Example source configuration](examples/sources.toml): source and limit settings.
- [Dockerfile](Dockerfile): reproducible Linux image build.
- [Pull request template](.github/pull_request_template.md): change and validation
  information for reviewers.
- [License](LICENSE): GNU Affero General Public License, version 3.

## Contributing

Read `CONTRIBUTING.md` before making changes. Keep contributions focused and
report the validation actually performed. Language and tooling decisions should
be documented when introduced rather than assumed from another repository.
