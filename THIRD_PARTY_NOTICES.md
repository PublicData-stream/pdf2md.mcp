# Third-party notices

## Obscura

The separate `pdf2md-obscura-worker` package depends on the upstream Obscura
project with its `stealth` feature enabled. The dependency is pinned to commit
[`e3007167016b169bb58d8b5124ca9662a0b37f2d`](https://github.com/h4ckf0r0day/obscura/tree/e3007167016b169bb58d8b5124ca9662a0b37f2d)
and is distributed under the Apache License, Version 2.0. See the upstream
[`LICENSE`](https://github.com/h4ckf0r0day/obscura/blob/e3007167016b169bb58d8b5124ca9662a0b37f2d/LICENSE)
file for the terms applicable to that code.

The root application and worker package are licensed under
[`AGPL-3.0-only`](LICENSE). This notice identifies the direct Obscura source
dependency; it is not a complete license or attribution inventory for every
transitive Rust dependency. The native browser and TLS components in the worker
dependency graph, including V8 and BoringSSL, need separate license and notice
review before preparing a release. Review dependency metadata and upstream
notices for the full graph.
