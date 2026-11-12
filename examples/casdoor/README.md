# Casdoor compatibility test

Run the disposable integration harness from the repository root:

```sh
export CARGO_TARGET_DIR=/tmp/rust/target
export TMPDIR=/tmp
python3 scripts/test-casdoor.py
```

Requirements are a reachable local Docker daemon, OpenSSL, Python 3, and the
project's Rust toolchain. Select your intended local Docker context before
running the script. The harness uses Casdoor 4.27.1 pinned to its published
image digest, serves HTTPS only on a loopback-bound port, and removes the
container and temporary directory after success or failure. Casdoor runs with
SQLite state, console logging and unprivileged LDAP/RADIUS ports. All generated
provider storage, certificates, synthetic credentials, and token fixtures live
under `/tmp`.

The harness loads one organization, two synthetic users and three Agent
applications with the `pdf2md:read`, `pdf2md:write` and `pdf2md:operate`
custom scopes from a Casdoor
[init data file](https://casdoor.ai/docs/deployment/data-initialization/):

| Application | Grants | Purpose |
| --- | --- | --- |
| `pdf2md-web` | Authorization Code, Implicit, Refresh Token, Device Authorization | Introspection client and registered client of the service |
| `pdf2md-short` | Authorization Code | 72-second access tokens for the JWT expiry check |
| `pdf2md-machine` | Client Credentials | Application identity |

Casdoor's sign-in page is a browser application. The harness and the Rust test
call the same JSON sign-in API that page uses, with the parameters of the
authorization URL, without a browser. This is test-client automation; the
service's own pages do not collect passwords.

The opt-in Rust test `tests/live_casdoor.rs` checks:

- Authorization Code with PKCE through `/oauth/login` and `/oauth/callback`,
  including the cookie-bound state and the RFC 9207 `iss` parameter.
- Implicit through `/oauth/login?grant=implicit`.
- Device Authorization through `/oauth/device` and `/oauth/token`, including
  `authorization_pending` before a second user approves the code.
- Refresh Token through `/oauth/token`, including rejection of a rotated
  refresh token.
- Client Credentials through the library client, as a separate workspace.
- Both validators with the `casdoor` token profile, configured scopes,
  private-workspace history and PDF access, rejection of ID and refresh
  tokens, immediate revocation through introspection, and JWT expiry. Local JWT
  verification does not establish immediate token revocation.

The test uses a generated trusted CA; TLS certificate verification remains
enabled.

Set `PDF2MD_CARGO_PROFILE` to select a separate Cargo profile inherited from
`dev` for this harness. Both its build and test invocations use that profile.
`PDF2MD_LIVE_CASDOOR_TEST_EXECUTABLE` selects a verified prebuilt test
executable. A provider-only smoke test can be run with
`PDF2MD_CASDOOR_SKIP_RUST=1`. This explicitly skips Rust acceptance and is not
equivalent to the full test.

For operator configuration, use the service's `[auth.oidc]` issuer, audience,
validation method, `token_profile = "casdoor"` and runtime secret references;
see [authentication](../../docs/authentication.md#token-profiles). Casdoor's
introspection endpoint reports refresh tokens as active `Bearer` tokens, and
its JWTs use the generic `JWT` header type, so the profile requires the signed
`tokenType` claim `access-token`. Configure the same resource URI as the
audience and request it as the RFC 8707 `resource`. Casdoor 4.27.1 binds
Implicit and Client Credentials tokens to the client ID instead; list those
dedicated client IDs in `additional_audiences`. Register clients explicitly;
this integration does not depend on Dynamic Client Registration.

References:

- [Casdoor OAuth 2.0 endpoints and grant types](https://casdoor.ai/docs/how-to-connect/oauth/)
- [Casdoor tokens](https://casdoor.ai/docs/token/overview/)
- [Casdoor custom scopes](https://casdoor.ai/docs/application/scopes/)
- [OAuth token introspection](https://www.rfc-editor.org/rfc/rfc7662.html)
- [Resource indicators](https://www.rfc-editor.org/rfc/rfc8707.html)

Passing this harness establishes local provider and library-boundary evidence.
It does not establish hosted CI, Kubernetes deployment, or MCP-client acceptance.

The same harness exercises the HTTP listener with real tokens in both
validation modes, including upload/conversion permissions, job/PDF isolation,
revocation, expiry, and recovery of previously accepted queued work. For
image-level Kubernetes acceptance, use `python3 scripts/test-http-oidc.py IMAGE`;
see [HTTP API validation](../../docs/http-api.md#validation).
