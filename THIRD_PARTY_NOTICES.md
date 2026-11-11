# Third-party notices

## jsonwebtoken

The core library uses [`jsonwebtoken` 10.4.0](https://crates.io/crates/jsonwebtoken/10.4.0)
for OAuth access-token signature verification. It is distributed under the
[MIT License](https://github.com/Keats/jsonwebtoken/blob/v10.4.0/LICENSE).
Cargo.lock records its RustCrypto dependency graph. This note does not replace
the complete dependency license review needed before distribution.

## Obscura

The separate `pdf2md-obscura-worker` package depends on the upstream Obscura
project with its `stealth` feature enabled. The dependency is pinned to commit
[`e3007167016b169bb58d8b5124ca9662a0b37f2d`](https://github.com/h4ckf0r0day/obscura/tree/e3007167016b169bb58d8b5124ca9662a0b37f2d)
and is distributed under the Apache License, Version 2.0. See the upstream
[`LICENSE`](https://github.com/h4ckf0r0day/obscura/blob/e3007167016b169bb58d8b5124ca9662a0b37f2d/LICENSE)
file for the terms applicable to that code.

The container build copies the upstream `LICENSE` (and `NOTICE`, when present)
from the Cargo checkout for this exact revision into
`/usr/share/licenses/pdf2md-mcp/obscura/`.

The root application and worker package are licensed under
[`AGPL-3.0-only`](LICENSE). This notice identifies the direct Obscura source
dependency; it is not a complete license or attribution inventory for every
transitive Rust dependency. The native browser and TLS components in the worker
dependency graph, including V8 and BoringSSL, need separate license and notice
review before preparing a release. Review dependency metadata and upstream
notices for the full graph.

## pdf_oxide

The `pdf2md-mcp` package uses [`pdf_oxide` 0.3.78](https://crates.io/crates/pdf_oxide/0.3.78)
for PDF parsing and Markdown conversion. Its Cargo manifest declares `MIT OR
Apache-2.0`; the upstream source includes `LICENSE-MIT`, `LICENSE-APACHE`, and
a `NOTICE` file. The container build resolves the locked crate through Cargo
metadata and copies those three files from the exact 0.3.78 checkout into
`/usr/share/licenses/pdf2md-mcp/pdf_oxide/`.

This notice identifies the direct conversion dependency; it is not a complete
license or attribution inventory for every transitive dependency. Review the
locked dependency metadata and included notices before distribution.
