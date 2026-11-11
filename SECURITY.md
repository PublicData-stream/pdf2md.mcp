# Security Policy

## Scope and Project Status

This policy covers the source, configuration, documentation, and project-owned
automation in `PublicData-stream/pdf2md.mcp`, including affected uses of
third-party dependencies in the current implementation.

The current implementation acquires remote or local PDF bytes and records
history; it does not fully parse PDFs, convert them to Markdown, or provide an
MCP server. No stable-release security support policy, maintenance window, or
backport commitment is established. Include the affected commit when reporting
a development issue.

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

Treat input PDFs and remote responses as untrusted. The current implementation
checks a PDF signature header only; it does not establish that a document is
well formed or safe to parse. Consider resource exhaustion, filesystem
boundaries, external-resource access, secret handling, browser process
isolation, and unsafe handling of generated Markdown as those features evolve.
The Obscura worker's resident memory is sampled against a configurable
threshold, but this is not a hard memory limit and there is no operating-system
sandbox. Assess dependency issues against actual usage and report relevant
vulnerabilities through the private channel above.
