# Authentication foundations

The library exposes `service::CallerService` for a future transport. It does
not start an HTTP or MCP listener, implement browser login, or issue tokens.
The local CLI and low-level storage APIs remain trusted operator interfaces.

## Modes and permissions

| `auth.mode` | Caller workspace | Caller operations |
| --- | --- | --- |
| `none_ro` (default) | Shared anonymous workspace | Status, history, PDF reads |
| `none_rw` | Same shared workspace | Reads and public HTTPS acquisition |
| `oauth2` | Private workspace for the exact issuer and subject | Scope-authorized reads and public HTTPS acquisition |

No-auth callers share data and do not have individual identities. A bearer
value supplied in either no-auth mode does not select a private workspace.
OAuth2 users cannot access the shared or operator workspace. Changing modes
preserves private workspaces and never publishes them anonymously.
Remove `[auth.oidc]` when selecting a no-auth mode; configuration rejects
provider settings in those modes rather than silently ignoring them.

The caller boundary checks permissions on each operation, before acquisition
effects. It does not accept source definitions, file paths, browser scripts,
cookies, operator credentials, polling schedules, or workspace selectors.
Read operations require the configured read scope. Acquisition requires both
the read and write scopes. Valid users with the required scopes are provisioned
automatically; email addresses, display names, and group membership are not
identity keys.

## Configuration

An omitted `[auth]` section selects `none_ro`. For anonymous writes:

```toml
[auth]
mode = "none_rw"
```

For Authelia's default opaque access tokens:

```toml
[auth]
mode = "oauth2"

[auth.oidc]
issuer = "https://auth.example.com"
audience = "https://pdf.example.com"
validation = "introspection"
access_token_prefix = "authelia_at_"
client_id = "pdf2md-resource"
client_secret = { env = "PDF2MD_OIDC_CLIENT_SECRET" }
read_scope = "pdf2md:read"
write_scope = "pdf2md:write"
```

Register the introspection client in the provider with `client_secret_basic`.
Authelia 4.39.28 omits the optional introspection token-type field, including
for refresh tokens. The explicit `access_token_prefix` distinguishes its
`authelia_at_` access-token class; remote active-token, audience, subject,
expiry, and scope checks are still mandatory. Without a configured prefix,
introspection requires a `Bearer` token-type response. JWT mode rejects the
prefix setting, so remove it when selecting `validation = "jwt"`.
Register user-facing clients for Authorization Code with PKCE S256, the service
audience, and these custom scopes. Token acquisition belongs to those clients;
this library does not provide a callback or dynamic client registration.
Keep subject/sector configuration stable: a changed provider subject creates
a different private workspace. Configure custom scopes and access-token
audiences using the [Authelia provider configuration](https://www.authelia.com/configuration/identity-providers/openid-connect/provider/)
and [client configuration](https://www.authelia.com/configuration/identity-providers/openid-connect/clients/).

Select `validation = "jwt"` for RS256 RFC 9068 access tokens. JWT mode does not
need introspection credentials. For Authelia 4.39.28 also set
`jwt_scope_claim = "scp"`, which selects its array of individual scope strings.
The default `"scope"` selects the standard space-separated string. Only the
configured claim grants permissions; the validator never merges claims or
falls back to the other claim. The nondefault setting is valid only in JWT
mode. This matches the pinned provider's
[JWT scope format](https://github.com/authelia/authelia/blob/v4.39.28/internal/oidc/config.go).
Configure Authelia's
`access_token_signed_response_alg` as `RS256`; an OIDC ID token is never a
substitute for an access token. Validators are selected explicitly, without
fallback. Introspection checks every operation without token-result caching.
Local JWT validation can continue accepting a revoked token until expiry;
choose introspection when prompt revocation is required.

Provider endpoints require HTTPS and trusted certificates. `ca_file` can add
a PEM trust anchor. `client_secret = { file = "secret" }` reads a regular
secret file instead of an environment variable. File references are relative
to the TOML file. OIDC secrets cannot be literal configuration values.
Discovery endpoints must use the issuer origin unless their origins appear
in `allowed_endpoint_origins`. Provider calls have a five-second timeout and
256 KiB response limit. Discovery and JWKS are cached for five minutes;
unknown key IDs can trigger one refresh per 30 seconds. TLS verification stays
enabled. Auth configuration is validated even for operator commands, but
operator commands do not authenticate to the provider.

## Library contract

Construct one `CallerService` per host with a data root, `Config`, and the
resolved optional PostgreSQL URL. `execute` takes the raw access-token value
(without `Bearer `), a typed `Operation`, and a cancellation token.

`Operation` supports `Status`, `History`, `ReadPdf`, and `AcquireHttps`.
Responses contain observations, an acquisition observation, or an `AsyncRead`
PDF stream. Streams retain their workspace handle until dropped. Documents
must appear in the selected workspace's accepted history; a known digest does
not grant access to another user's objects. No filesystem path is returned.

`auth_invalid`, `auth_forbidden`, and `auth_unavailable` distinguish credential,
permission, and provider failures without exposing tokens or provider bodies.
`service_busy` reports exhausted acquisition capacity or active workspace
handles. Acquisition admission uses the existing aggregate concurrency setting.
The store cache holds at most 32 workspaces, evicting idle handles only. This is
application authorization and storage separation, not an operating-system
sandbox, per-user disk quota, or hard CPU/memory isolation.
PDF reads verify the complete object's digest before streaming; this work is
separate from acquisition admission and should be considered when adding a
public transport.

## Operator storage and backups

Existing data at the data root remains operator-private and keeps metadata
schema version 1. New caller workspaces live under `workspaces/<UUID>/`, each
with separate objects, staging, inbox, and store identity. Identical PDFs are
deduplicated only within one workspace. SQLite metadata lives in each root;
PostgreSQL uses the existing store-specific namespaces.

The local `workspaces.sqlite3` registry associates exact issuer/subject pairs
and the shared workspace with opaque UUIDs. Its separate versioned schema does
not change acquisition metadata. It contains sensitive identity metadata.
Provisioning is serialized and resumes interrupted initialization. Do not edit
registry mappings or replace workspace store identities manually.

The trusted CLI defaults to `--workspace operator`. Use
`--workspace shared` or an initialized UUID to select another workspace for
normal operator commands. `workspaces --json` lists initialized workspaces and
their identity mapping. Operator writes remain available in `none_ro`, so the
operator can populate read-only shared data. For example:

```sh
pdf2md-mcp --data-dir ./pdf2md-mcp-data --workspace shared scan
pdf2md-mcp --data-dir ./pdf2md-mcp-data workspaces --json
pdf2md-mcp --data-dir ./pdf2md-mcp-data --workspace shared history
```

`scan` creates/selects the workspace inbox; place PDFs in that workspace's
`pdfs/` directory before scanning again. Operator-configured sources and
credentials are used only when an operator explicitly runs those commands.
Only one writer can own an individual workspace at a time; stop the caller
host before using CLI writes to one of its cached workspaces.

Keep the metadata backend fixed for a data root. Back up the registry,
operator root, all workspace roots, and external PostgreSQL metadata together
while writers are stopped. Restore them together. No data move or relabeling is
needed to adopt these foundations. Downgrading does not expose caller
workspaces through the original operator CLI.

## Verification

Core auth, service, and workspace tests run with the documented
`cargo test --locked --package pdf2md-mcp` command. Tests use synthetic PDFs
and disposable TLS providers. PostgreSQL tests additionally require
`PDF2MD_TEST_POSTGRES_URL` pointing to PostgreSQL 18 or newer.

Live Authelia checks use a disposable provider with two synthetic users and
registered test clients. They exercise real opaque/JWT access tokens,
permissions, isolation, revocation, and expiry against the library boundary.
Provider compatibility does not establish HTTP/MCP client or deployment
acceptance. Run `python3 scripts/test-authelia.py`; see
[the live harness guide](../examples/authelia/README.md) for requirements and
provider configuration.
