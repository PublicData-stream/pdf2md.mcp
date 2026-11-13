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

The harness loads one organization, two synthetic users and four Agent
applications with the `pdf2md:read`, `pdf2md:write` and `pdf2md:operate`
custom scopes from a Casdoor
[init data file](https://casdoor.ai/docs/deployment/data-initialization/):

| Application | Grants | Purpose |
| --- | --- | --- |
| `pdf2md-web` | Authorization Code, Refresh Token, Device Authorization | Introspection client and registered client of the service |
| `pdf2md-short` | Authorization Code | 72-second access tokens for the JWT expiry check |
| `pdf2md-machine` | Client Credentials | Application identity, also with a DPoP-bound token |
| `pdf2md-assertion` | Client Credentials | `private_key_jwt` client and introspection client |

Casdoor's sign-in page is a browser application. The harness and the Rust test
call the same JSON sign-in API that page uses, with the parameters of the
authorization URL, without a browser. This is test-client automation; the
service's own pages do not collect passwords.

The opt-in Rust test `tests/live_casdoor.rs` checks:

- Authorization Code with PKCE through `/oauth/login` and `/oauth/callback`,
  including the cookie-bound state and the RFC 9207 `iss` parameter.
- That the result page shows no refresh token, and that no HTTP route redeems
  a device code or refresh token.
- Device Authorization through the library client, including
  `authorization_pending` before a second user approves the code.
- Refresh Token through the library client, including rejection of a rotated
  refresh token.
- Client Credentials through the library client, as a separate workspace.
- `private_key_jwt`: Client Credentials and introspection authenticated with a
  signed assertion instead of a shared secret.
- DPoP: a token that Casdoor bound to a key is accepted over HTTP with a fresh
  proof from that key, and refused as a Bearer token, without a proof, with a
  replayed proof, with another key's proof and with a proof made for another
  token.
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
Client Credentials tokens to the client ID instead; list those dedicated
client IDs in `additional_audiences`. Register clients explicitly;
this integration does not depend on Dynamic Client Registration.

### Signed client assertions and DPoP

For `private_key_jwt`, the harness generates an RSA key and a self-signed
certificate with OpenSSL and registers the certificate as the client
certificate of `pdf2md-assertion`. See
[Client authentication with a signed assertion](../../docs/authentication.md#client-authentication-with-a-signed-assertion)
for the service configuration. Casdoor 4.27.1 has these particulars:

- The assertion's `iss` must be a registered redirect URI of the application,
  so the test sets `issuer` to the registered callback URL.
- Casdoor's JWKS lists every certificate of type `x509`, and Casdoor replaces a
  certificate stored without a private key by a generated key pair. The
  harness therefore stores the client certificate under the `Payment` type
  with a placeholder instead of the private key, and fails when the provider's
  JWKS lists the client key. The private key stays with the client.

For DPoP, the test requests a Client Credentials token with a proof for
Casdoor's token endpoint. Casdoor reports the bound key only through
introspection, so the test validates with `validation = "introspection"` and
`[auth.oidc.dpop]`; see
[DPoP-bound access tokens](../../docs/authentication.md#dpop-bound-access-tokens).

References:

- [Casdoor OAuth 2.0 endpoints and grant types](https://casdoor.ai/docs/how-to-connect/oauth/)
- [Casdoor tokens](https://casdoor.ai/docs/token/overview/)
- [Casdoor custom scopes](https://casdoor.ai/docs/application/scopes/)
- [OAuth token introspection](https://www.rfc-editor.org/rfc/rfc7662.html)
- [JWT client authentication](https://www.rfc-editor.org/rfc/rfc7523.html)
- [DPoP](https://www.rfc-editor.org/rfc/rfc9449.html)
- [Resource indicators](https://www.rfc-editor.org/rfc/rfc8707.html)

Passing this harness establishes local provider and library-boundary evidence.
It does not establish hosted CI, Kubernetes deployment, or MCP-client acceptance.

The same harness exercises the HTTP listener with real tokens in both
validation modes, including upload/conversion permissions, job/PDF isolation,
revocation, expiry, and recovery of previously accepted queued work. For
image-level Kubernetes acceptance, use `python3 scripts/test-http-oidc.py IMAGE`;
see [HTTP API validation](../../docs/http-api.md#validation).
