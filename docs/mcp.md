# MCP tools

The `serve` process can expose eight read-only tools over Streamable HTTP at
`/mcp`. Enable the endpoint explicitly; existing configurations leave it off:

```toml
[mcp]
enabled = true
```

The existing HTTP API continues to handle uploads, acquisition and conversion
jobs. These tools retrieve existing conversions; they do not create or retry
conversions. There is no stdio transport or separate MCP resources interface.
Protocol revisions `2026-07-28` and `2025-11-25` are supported. Clients should
use a compatible MCP SDK rather than construct protocol metadata themselves.

## Authentication

MCP uses the configured caller mode and `pdf2md:read` scope (or the configured
read scope). `none_ro` and `none_rw` expose the same shared workspace used by
the HTTP API. OAuth2/OIDC identifies a workspace by the exact issuer and subject;
all eight tools, including workspace-wide search, stay inside that workspace.
A conversion ID does not grant access to another user's document.

For OAuth, configure the externally visible resource identifier and permitted
browser origins explicitly:

```toml
[mcp]
enabled = true
resource_url = "https://pdf.example.com/mcp"
allowed_origins = ["https://client.example.com"]
```

The endpoint accepts bearer access tokens through the HTTP Authorization
header. Configure the provider to issue access tokens for the existing
`auth.oidc.audience`, and ensure that clients requesting the advertised resource
receive that audience. The service preserves the configured token validator;
it does not issue tokens or register OAuth clients. Use provider-side client
registration with Authorization Code and PKCE where appropriate.

OAuth protected-resource metadata advertises the configured issuer and read
scope. Authentication challenges link to that metadata. Keep the public URL
consistent with ingress routing; it is not inferred from Host or forwarded
headers. Supplied Origin headers must match `allowed_origins`; clients without
an Origin header can connect. An empty allowlist rejects every supplied origin.
Local JWT validation retains its existing revocation limitations; introspection
revalidates active tokens according to the provider. See
[authentication](authentication.md) for the operator/caller boundary.

## Inventory and identifiers

`list` accepts `kind` (`documents`, `conversions`, `sections`, or `blocks`),
`limit`, and `cursor`. The default kind is `documents`. Use `document_id` to
filter conversion history and `conversion_id` to list sections or blocks.
Inventory includes retained history, rather than only the latest conversion.

Use an exact successful `conversion_id` for subsequent tools. A document ID
identifies original PDF bytes, while a conversion ID fixes the selected pages,
converter profile, and immutable Markdown. A conversion may cover only part of
a PDF; inspect its page coverage before treating it as the entire PDF.

Sections and blocks include source byte and line spans. IDs are local to an
exact conversion. Sections begin at a document-level Markdown heading of any level and include nested
subsections through the next heading of equal or higher level. Blocks describe
parsed Markdown structure, including nested blocks and parent IDs. Generated
page markers and separators do not become structural entries.

Inventory defaults to 100 entries per response, with a maximum of 500. Follow
`next_cursor` until absent. Cursors are bound to the caller and request;
service restarts invalidate them.

## Reading Markdown

- `read` takes `conversion_id` and returns the **entire stored `document.md`**,
  without trimming or summarizing it. This includes Markdown syntax, generated
  page comments, image references, whitespace, and its final newline.
- `read-page` takes `conversion_id` and `pages`, for example `"1-3,7"`.
  Page numbers refer to the original PDF, starting at 1. Selections are sorted
  and deduplicated. Every selected page must exist in that conversion.
- `read-section` takes `conversion_id` and a required `selectors` array of
  1–500 section/block selections. Obtain IDs from
  `list(kind="sections"|"blocks", conversion_id=...)`; these IDs are scoped to
  that exact conversion, not to PDF bookmarks from `table`.
- `table` takes `conversion_id` and returns embedded PDF outlines/bookmarks
  as Markdown. It preserves hierarchy and available page destinations, and
  identifies unresolved destinations. It does not recognize printed contents
  pages or generate a contents table from Markdown headings. Absence and
  unavailable extraction are distinct results.

`read-page` returns complete selected page chunks, including their page markers
and excluding the generated separator between pages. It does not parse page
boundaries from document text.

The default text budget is 8 MiB for `read`, a selected `read-page` response,
or the combined selected text in `read-section`.
Oversized selections fail with a size error: no partial document is returned.
Use smaller page selections or the authenticated HTTP Markdown download for
larger documents. Client-side context or response limits can be smaller than
the server budget.

For example, select a section and a block from the Markdown inventory:

```json
{
  "conversion_id": "CONVERSION_ID",
  "selectors": [
    {"kind": "section", "id": "s1"},
    {"kind": "block", "id": "b3"}
  ]
}
```

`read-section` returns JSON in both structured content and the MCP text content:
`{conversion_id, bytes, results}`. Each result contains the original `selector`,
the corresponding inventory entry as `span`, its UTF-8 `bytes`, and exact source
`text`. Byte spans use an inclusive `start` and exclusive `end`; line spans are
1-based and inclusive. Results preserve request order and source whitespace,
Markdown syntax, image references, and any generated page markers or separators
within the selected range. Sections include nested subsections. Overlapping
selections remain separate results, and repeated text counts toward the combined
budget. The budget excludes JSON encoding and metadata. A selection exactly at
the budget succeeds, even when the whole document is larger.

The entire call fails without partial content on an error. Malformed, empty,
oversized, or duplicate selector arrays return `invalid_arguments`; missing IDs
or IDs used with the wrong selector kind return `selector_not_found`. An
unavailable structure index returns `metadata_unavailable`, and selections above
the read budget return `size_limit`. Bundle and index corruption retain the
existing integrity errors. Reading a small selection still verifies the index
against the complete stored Markdown using bounded streaming reads.

## Line and byte measurements

`count` returns source-line counts. `size` returns exact UTF-8 source-byte
counts. Both take `conversion_id` and an optional `selectors` array:

```json
{
  "conversion_id": "CONVERSION_ID",
  "selectors": [
    {"kind": "whole"},
    {"kind": "section", "id": "s1"},
    {"kind": "block", "id": "b1"},
    {"kind": "lines", "start": 2, "end": 10}
  ]
}
```

Omitting selectors measures the whole Markdown file. Each result is independent;
overlapping selectors are not summed, and duplicate selectors are invalid.
Line ranges are inclusive and 1-based; invalid ranges fail explicitly.
Measurements include Markdown syntax, whitespace and generated comments within
the selected span. They exclude image bytes, bundle metadata, and JSON encoding.

Empty text has zero lines. Otherwise, count LF characters and add one if the
last byte is not LF. Thus `a\n` and `a` each have one line, `a\n\n` has two,
and CRLF is one line ending. A lone CR is ordinary source content. UTF-8 byte
counts differ from character counts for non-ASCII text.

## Searching

`rg` runs real ripgrep over verified converted Markdown. Example arguments:

```json
{
  "pattern": "public notice",
  "conversion_ids": ["CONVERSION_ID"],
  "literal": true,
  "case": "insensitive",
  "word": false,
  "context": 1,
  "limit": 200
}
```

Omitting `conversion_ids` searches every retained successful conversion in the
caller's workspace, including historical and selected-page conversions.
Different conversions can therefore produce repeated text. Results identify
conversions and source lines, with match offsets and page numbers when indexed.
Case modes are `sensitive` (default), `insensitive`, and `smart`. Patterns use
ripgrep's default regex engine unless `literal` is true. Context is limited to
20 lines. Filesystem paths and arbitrary command-line arguments are not inputs.

Search defaults to 200 matching lines per page, a maximum of 1,000, an 8 MiB
response budget, a 30-second deadline, and four concurrent searches. Follow the
returned continuation cursor with the same search arguments. Workspace-wide
pagination preserves a conversion snapshot; newly completed conversions appear
in a new search. Deadline/output limits are reported as incomplete results,
not as proof that the workspace contains no further matches.

Install `rg` on the service host; the container image includes it. The configured
`rg_path` is a trusted operator setting. Missing executables and invalid regex
patterns return explicit errors.

## Configuration and retained bundles

Optional `[mcp]` settings include `max_read_bytes`, `list_default_limit`,
`list_max_limit`, `search_default_limit`, `search_max_limit`, `search_max_bytes`,
`search_timeout_secs`, `search_concurrency`, and `rg_path`. Defaults are the
limits described above. Configuration is validated at service startup. Read/search byte budgets cannot
exceed 64 MiB (search budgets have a 4096-byte minimum), and search timeouts cannot exceed 300 seconds.

New conversions use bundle format v2 and conversion profile v2, with hashed
`text-index.json` and `outline.json` artifacts. Metadata remains subject to
conversion output, timeout, and process resource limits. The following
`[conversion.limits]` settings can lower metadata limits: `max_index_bytes`
(default 16 MiB, minimum 4096), `max_index_entries` (100,000),
`max_outline_bytes` (1 MiB, minimum 256), `max_outline_entries` (10,000), and
`max_outline_depth` (64). Defaults are also hard ceilings. Metadata limits are
reported explicitly rather than silently clipping an index or outline.

Existing v1 bundles remain immutable and readable. Whole-file reads, searches,
and whole-file or line-range measurements work on them. Page reads, outlines,
and section/block selection (including `read-section`) return `upgrade_required`;
request a new conversion through the trusted CLI or HTTP conversion API. There
is no automatic backfill.

## Verification

Run the documented core Rust checks, including the MCP HTTP/tool integration
tests. The HTTP container harness exercises the eight tools and restart reads:

```sh
python3 scripts/test-http.py IMAGE --minikube
python3 scripts/test-http-oidc.py IMAGE
```

The second harness tests real OIDC tokens, two-user isolation, and JWT and
introspection validation in a disposable minikube cluster. State and credentials
remain under `/tmp`. These checks do not establish compatibility with an
external client UI, hosted CI success, or a production deployment.
