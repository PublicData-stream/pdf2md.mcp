# Authentication foundations

The HTTP service uses the caller authorization boundary and accepts bearer
access tokens in OAuth2 mode. It is an OAuth resource server: the identity
provider issues, refreshes and revokes tokens, clients store them, and this
service only validates the access token on each request. It never issues,
stores or refreshes tokens for HTTP callers. An optional registered OAuth
client supports the Authorization Code, Device Authorization, Refresh Token
and Client Credentials grants for browser sign-in and the trusted CLI; see
[Obtaining access tokens](#obtaining-access-tokens). The local CLI and
low-level storage APIs remain trusted operator interfaces. See
[the HTTP API](http-api.md) for routes and job behavior.

## Modes and permissions

| `auth.mode` | Caller workspace | Caller operations |
| --- | --- | --- |
| `none_ro` (default) | Shared anonymous workspace | Status, history, PDF and conversion reads |
| `none_rw` | Same shared workspace | Reads, uploads, public HTTPS acquisition and conversion |
| `oauth2` | Private workspace for the exact issuer and subject | Scope-authorized reads, writes and conversion |

No-auth callers share data and do not have individual identities. A bearer
value supplied in either no-auth mode does not select a private workspace.
OAuth2 users cannot access the shared or operator workspace. Changing modes
preserves private workspaces and never publishes them anonymously.
Remove `[auth.oidc]` when selecting a no-auth mode; configuration rejects
provider settings in those modes rather than silently ignoring them.

The caller boundary checks permissions on each operation, before acquisition
effects. It does not accept source definitions, file paths, browser scripts,
cookies, operator credentials, or workspace selectors. Published source execution
and schedule changes have an operator-controlled allowlist and operate scope.
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

For [Casdoor](https://casdoor.ai/docs/how-to-connect/oauth/) with token
introspection:

```toml
[auth]
mode = "oauth2"

[auth.oidc]
issuer = "https://auth.example.com"
audience = "https://pdf.example.com/"
validation = "introspection"
token_profile = "casdoor"
client_id = "pdf2md-introspection"
client_secret = { env = "PDF2MD_OIDC_CLIENT_SECRET" }
read_scope = "pdf2md:read"
write_scope = "pdf2md:write"
operate_scope = "pdf2md:operate"
```

Introspection authenticates with `client_secret_basic`. Select
`validation = "jwt"` to verify RS256 access tokens locally with the provider's
JWKS; JWT mode does not need introspection credentials. Validators are selected
explicitly, without fallback. Introspection checks every operation without
token-result caching. Local JWT validation can continue accepting a revoked
token until expiry; choose introspection when prompt revocation is required.

Expiry is enforced without leeway. The not-yet-valid checks (`nbf` and `iat`)
tolerate a provider clock up to 30 seconds ahead, because providers issue
whole-second timestamps and a freshly issued token can otherwise be rejected.

In OAuth2 mode, API responses to requests that carried Bearer credentials
follow [RFC 6750 section 3.1](https://www.rfc-editor.org/rfc/rfc6750#section-3.1):
HTTP 401 sends `WWW-Authenticate: Bearer error="invalid_token"` and HTTP 403
sends `Bearer error="insufficient_scope"`. Requests without credentials
receive the bare `Bearer` challenge.

### Token profiles

`token_profile` selects how an access token is distinguished from the
provider's other tokens. The validator never falls back between profiles.

| `token_profile` | JWT validation | Introspection |
| --- | --- | --- |
| `rfc9068` (default) | [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html): header `typ` `at+jwt` and a `client_id` claim | `token_type` `Bearer`, or an explicit `access_token_prefix` when the provider omits it |
| `casdoor` | Header `typ` `JWT`, signed `tokenType` claim `access-token`, and an `azp` claim | The token must be a JWT whose `tokenType` is `access-token`, and the introspected `jti` must match it |

Casdoor signs access, refresh and ID tokens with the same key, and its
introspection endpoint reports refresh tokens as active `Bearer` tokens. The
`casdoor` profile therefore requires the access-token class carried by the
token itself. Introspection looks up the exact token string, so the provider
authenticates that claim; it is checked before the provider is called. The
`casdoor` profile requires the default `jwt_scope_claim = "scope"` and rejects
`access_token_prefix`. Configure Casdoor's
[token format](https://casdoor.ai/docs/token/overview/) as `JWT-Standard` or
`JWT-Empty` to keep user attributes out of access tokens; the validator uses
only `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, `azp`, `scope` and
`tokenType`.

For other providers, `access_token_prefix` restricts introspection to an
issuer-documented access-token prefix when the provider omits the optional
token-type field. Remote active-token, audience, subject, expiry, and scope
checks remain mandatory. JWT mode rejects the prefix setting.
`jwt_scope_claim = "scp"` selects an array of individual scope strings instead
of the standard space-separated `scope` claim, in JWT mode only. Only the
configured claim grants permissions; the validator never merges claims. An
OIDC ID token is never a substitute for an access token.

### Audiences

Access tokens must name `audience` in `aud`. Register it as the
[RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) resource of user-facing
clients; Casdoor then issues Authorization Code, Device Authorization and
Refresh Token grants for that resource. Casdoor 4.27.1 ignores the resource
indicator for the Client Credentials grant and sets `aud` to the requesting
client ID. To accept those tokens, list dedicated client IDs in
`additional_audiences` (at most 16):

```toml
additional_audiences = ["pdf2md-machine"]
```

Only list clients registered exclusively for this service: any access token
issued to them is accepted, whichever resource it was requested for. Prefer
grants that the provider binds to the resource, and leave the list empty when
you do not use Client Credentials. ID tokens remain rejected by the token
profile.

When the MCP endpoint is enabled, its `resource_url` must equal `audience` or
appear in `additional_audiences`; configuration is rejected otherwise. MCP
clients request tokens for the advertised resource, so the validator has to
accept exactly that value.

### Provider registration

Register clients explicitly; this integration does not depend on Dynamic
Client Registration. Give each MCP client or other API client its own provider
application, as a public client using Authorization Code with PKCE where it
cannot keep a secret. Clients then obtain, store and refresh their tokens
directly with the provider, which can grant consent to and revoke each client
separately. Use a separate confidential application for introspection. In
Casdoor, create an application with the **Agent**
category and define the custom scopes `pdf2md:read`, `pdf2md:write` and
`pdf2md:operate` ([custom scopes](https://casdoor.ai/docs/application/scopes/)).
Enable only the grant types you use. Keep subject configuration stable: a
changed provider subject creates a different private workspace. Casdoor user
subjects are user IDs; Client Credentials tokens use the application's
`owner/name` as subject, so each machine client receives its own workspace.

### Provider connections

Provider endpoints require HTTPS and trusted certificates. `ca_file` can add
a PEM trust anchor. `client_secret = { file = "secret" }` reads a regular
secret file instead of an environment variable. File references are relative
to the TOML file. OIDC secrets cannot be literal configuration values.
Discovery endpoints must use the issuer origin unless their origins appear
in `allowed_endpoint_origins`. Provider calls have a five-second timeout and
256 KiB response limit. Discovery and JWKS are cached for five minutes;
unknown key IDs can trigger one refresh per 30 seconds. TLS verification stays
enabled. Auth configuration is validated even for operator commands; only the
`oauth` commands contact the provider.

## Obtaining access tokens

API and MCP clients normally obtain tokens from the provider with their own
registered client; this service only needs to validate them. The optional
`[auth.client]` section additionally registers this service as an OAuth client
of the same issuer, for interactive sign-in to the bundled API console and for
the trusted CLI. It supports these grants:

| `grant_types` value | Grant | Where |
| --- | --- | --- |
| `authorization_code` | Authorization Code with PKCE S256 ([RFC 6749 section 4.1](https://www.rfc-editor.org/rfc/rfc6749#section-4.1), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)) | Browser: `GET /oauth/login`, then `GET /oauth/callback` |
| `device_code` | Device Authorization ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)) | `pdf2md-mcp oauth device` only |
| `refresh_token` | Refresh Token ([RFC 6749 section 6](https://www.rfc-editor.org/rfc/rfc6749#section-6)) | `pdf2md-mcp oauth refresh` only |
| `client_credentials` | Client Credentials ([RFC 6749 section 4.4](https://www.rfc-editor.org/rfc/rfc6749#section-4.4)) | `pdf2md-mcp oauth client-credentials` only |

Only Authorization Code has HTTP routes. The HTTP service never redeems a
device code or refresh token supplied by a caller, and never returns a refresh
token: doing so would apply the registered client's credentials to grants
held by anonymous callers. Those grants run from the CLI, where the operator
holds the client configuration, or between a caller's own client and the
provider.

Two OAuth 2.0 grants are not supported, and configuration rejects their
`grant_types` values:

- Resource Owner Password Credentials (`password`): the service never receives
  user passwords.
- Implicit (`implicit`): it returns the access token in the redirect URL, is
  deprecated by the
  [OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700#section-2.1.2)
  and is omitted from OAuth 2.1. Use Authorization Code with PKCE instead.

```toml
[auth.client]
client_id = "pdf2md-web"
client_secret = { env = "PDF2MD_OAUTH_CLIENT_SECRET" }
grant_types = ["authorization_code"]
scopes = ["pdf2md:read", "pdf2md:write"]
redirect_base_url = "https://pdf.example.com"
```

`[auth.client]` requires `mode = "oauth2"` and uses the `[auth.oidc]` issuer,
trust anchors and endpoint-origin rules. Omit `client_secret` for a public
client, which then sends `client_id` in each request; Client Credentials
requires a secret. The secret is sent with `client_secret_basic`. Every request
carries `resource`, which defaults to `[auth.oidc] audience`. Authorization
Code requires `redirect_base_url`, the public HTTPS origin of this service
(loopback HTTP is allowed for development). Register
`<redirect_base_url>/oauth/callback` as the client's redirect URI. Use a provider application separate from the
one used for introspection, so that sign-in and token validation can be
revoked and rotated independently. Routes for disabled grants are not
registered.

Browser sign-in:

- `/oauth/login` redirects to the provider with a random `state` and an S256
  PKCE challenge; the verifier stays in server memory for ten minutes. At most 8,192 sign-ins are pending at once; a newer sign-in replaces
  the oldest one when the table is full. The `state` is also bound to the
  browser with an `HttpOnly`, `SameSite=Lax` cookie, `Secure` for HTTPS.
- `/oauth/callback` requires the matching cookie and single-use `state`, then
  checks the [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207) `iss`
  parameter. It is mandatory when the provider advertises it, as Casdoor does.
  The code is redeemed with its verifier, and a result page shows the access
  token. ID tokens and refresh tokens are never displayed; sign in again when
  the access token expires.

Pages share a dark-only stylesheet (`/oauth/oauth.css`) in the GitHub Dark
color range and a copy-button script (`/oauth/page.js`), with no inline scripts
or styles. The result page
shows the token type, lifetime and granted scopes next to the access token. Browser
navigations that send `Accept: text/html` receive an HTML error page from
`/oauth/login` and `/oauth/callback` with the same status, error code and
request ID as the JSON error; other clients keep the JSON body. Provider error
descriptions are never shown. Responses use `Cache-Control: no-store`,
`Referrer-Policy: no-referrer` and a content security policy that allows only
same-origin scripts and styles.

Provider errors become fixed codes without provider descriptions:
`oauth_authorization_pending`, `oauth_slow_down`, `oauth_access_denied`,
`oauth_expired_token`, `oauth_invalid_grant`, `oauth_client_rejected`,
`oauth_invalid_scope`, `oauth_invalid_target` or `oauth_error`. Sign-in errors
use `oauth_state_mismatch`, `oauth_issuer_mismatch` and
`oauth_grant_disabled`. Network and malformed-response failures use
`auth_unavailable`.

The CLI reads the same configuration and prints the token response as JSON on
standard output: `access_token`, `token_type`, `expires_in`, `scope` and, when
issued, `refresh_token`. Treat that output as a credential and keep it out of
logs. Device authorization prints the verification URI and code on
standard error and polls until approval, denial or expiry, slowing down when
asked. Refresh reads the token from a named environment variable so it does
not appear in process arguments. Casdoor rotates refresh tokens by default;
store the new value:

```sh
pdf2md-mcp --config pdf2md.toml oauth device
pdf2md-mcp --config machine.toml oauth client-credentials
PDF2MD_REFRESH_TOKEN=... pdf2md-mcp --config pdf2md.toml oauth refresh --refresh-token-env PDF2MD_REFRESH_TOKEN
```

Use a separate configuration with a dedicated machine client for Client
Credentials, and add that client ID to `additional_audiences` when the
provider does not bind its tokens to the resource. Obtained tokens are ordinary
bearer credentials: they are validated on every request exactly like tokens
from any other client.

## Library contract

Construct one `CallerService` per host with a data root, `Config`, and the
resolved optional PostgreSQL URL. `execute` takes the raw access-token value
(without `Bearer `), a typed `Operation`, and a cancellation token.

`execute` remains the synchronous compatibility API. Typed methods add streaming
upload sessions, durable job submissions, job/schedule controls, conversion
queries, and verified artifact/bundle readers. Run `CallerService::run` alongside
the listener to dispatch durable work; it does not start an HTTP listener itself.

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
PDF and artifact reads verify their content before streaming. Download admission
is bounded separately from acquisition admission; streams retain the workspace
and download lease until dropped.

## Operator storage and backups

Existing data at the data root remains operator-private. Conversion history
upgrades metadata schemas 1 and 2 to version 3 when the store opens;
acquisition/conversion history, PDF objects, and bundles are preserved. Version 3
adds durable API jobs, idempotency records, retry links, and polling grants.
New caller workspaces
live under `workspaces/<UUID>/`, each with separate PDF objects, conversion
bundles, staging, inbox, and store identity. Identical PDFs are
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
credentials are used by trusted CLI commands and explicitly published caller
operations and durable schedule grants.
Only one writer can own an individual workspace at a time; stop the caller
host before using CLI writes to one of its cached workspaces.

Keep the metadata backend fixed for a data root. Back up the registry,
operator root, all workspace roots, and external PostgreSQL metadata together
while writers are stopped. Restore them together. The schema migration
is forward-only; older binaries cannot open schema 3 metadata. Before
upgrading, take a coordinated backup so a downgrade can restore the previous
metadata schema and matching filesystem data together. Downgrading does not expose
caller workspaces through the original operator CLI.

## Verification

Core auth, service, and workspace tests run with the documented
`cargo test --locked --package pdf2md-mcp` command. Tests use synthetic PDFs
and disposable TLS providers. PostgreSQL tests additionally require
`PDF2MD_TEST_POSTGRES_URL` pointing to PostgreSQL 18 or newer.

Registered-client grants run against a synthetic TLS provider in
`tests/oauth_client.rs` as part of the core suite.

Live Casdoor checks use a disposable provider with two synthetic users and
registered test clients. They exercise all four supported grants through the
registered client (Authorization Code over HTTP, the others through the library
client), both validators, permissions, isolation, revocation,
expiry, and durable job recovery against the library and HTTP boundaries.
These checks alone do not establish MCP client or Kubernetes deployment
acceptance. Run `python3 scripts/test-casdoor.py`; see
[the live harness guide](../examples/casdoor/README.md) for requirements and
provider configuration.

## MCP authorization

The opt-in MCP endpoint uses these same modes, scopes, token validators, and
issuer/subject workspace boundaries. It requires explicit public-resource
configuration in OAuth mode and advertises protected-resource metadata. See
[MCP tools](mcp.md#authentication). All eight tools require only read access.
