# Security Policy

## Scope and Project Status

This policy covers the source, configuration, documentation, and project-owned
automation in `PublicData-stream/pdf2md.mcp`, including affected uses of
third-party dependencies in the current implementation.

The current implementation acquires remote or local PDF bytes, converts
accepted PDFs to Markdown through `pdf_oxide`, and records acquisition and
conversion history. Conversion runs in a separate worker process through the
trusted CLI or daemon; it is not a caller-service operation. The library caller
service supports anonymous RO/RW and OAuth2/OIDC modes, with separate per-user
workspace roots and application authorization. The CLI and raw storage/library
APIs remain trusted operator interfaces. The project does not provide OCR or
an MCP server. No stable-release security support policy, maintenance window,
or backport commitment is established. Include the affected commit when
reporting a development issue.

## Reporting a Vulnerability

Use [GitHub private vulnerability reporting](https://github.com/PublicData-stream/pdf2md.mcp/security/advisories/new)
for undisclosed security issues. Do not reveal an unpatched vulnerability in
public issues, discussions, pull requests, or commit messages.

Include, when available:

- The affected commit, component, and relevant configuration.
- Attacker prerequisites, impact, and a minimal reproduction.
- A small synthetic input document instead of a private or sensitive PDF.
- Sanitized logs and any proposed mitigation.

Never include production credentials, private keys, tokens, personal data, or
unnecessary document content. If a reproduction requires sensitive material,
describe that constraint before sharing it.

## Triage and Disclosure

Maintainers assess reproducibility, affected code paths, exploitability, and
impact before choosing a fix or mitigation. Reports should remain private
while validation, remediation, and any upstream coordination are in progress.
Coordinate public disclosure after a fix or actionable mitigation is available;
maintainers may adjust timing for issues already public or actively exploited.
Reporter credit requires consent.

No acknowledgement or remediation response-time guarantee is established.
This policy does not authorize testing systems or accessing documents without
their owner's permission.

## Security Considerations for Contributions

See [Authentication foundations](docs/authentication.md) for identity, scope,
token validation, and workspace boundaries. No-auth RW callers share one
workspace. OAuth2 identities use exact issuer and subject pairs. Local JWT
validation does not establish immediate revocation; use introspection when
that is required. Workspace separation does not provide an operating-system
sandbox or per-user resource quotas. Provider credentials and the local
workspace registry are sensitive operator data.

Treat input PDFs and remote responses as untrusted. Acquisition checks a PDF
signature header only; conversion parses the document in a separate worker
process. Conversion has configurable input, page, timeout, address-space, image,
output, and concurrency limits, plus an asset-count cap. These controls do not
provide an operating-system sandbox. Review worker process supervision,
resource-limit enforcement, output-path validation, immutable bundle
publication, filesystem boundaries, external-resource access, secret handling,
browser process isolation, and unsafe handling of generated Markdown. The
Obscura worker's resident memory is sampled against a configurable threshold,
but this is not a hard memory limit. Assess dependency issues against actual
usage and report relevant vulnerabilities through the private channel above.
