# Keycloak compatibility test

Run the disposable integration harness from the repository root:

```sh
export CARGO_TARGET_DIR=/tmp/rust/target
export TMPDIR=/tmp
python3 scripts/test-keycloak.py
```

Requirements are a reachable local Docker daemon, OpenSSL, Python 3, and the
project's Rust toolchain. Select your intended local Docker context before
running the script. The harness uses Keycloak 26.8.2 pinned to its published
image digest, runs it in production mode (`start`) with HTTPS only on a
loopback-bound port and a fixed public hostname, and removes the container and
temporary directory after success or failure. Keycloak keeps its development
file database inside the disposable container. Generated certificates,
synthetic credentials, the realm import and token fixtures live under `/tmp`.

The harness writes one realm, `pdf2md`, and Keycloak loads it at startup with
`--import-realm`
([importing a realm](https://www.keycloak.org/server/importExport)). The realm
has two synthetic users, the optional client scopes `pdf2md:read`,
`pdf2md:write` and `pdf2md:operate`, and these confidential clients:

| Client | Grants | Purpose |
| --- | --- | --- |
| `pdf2md-web` | Authorization Code, Refresh Token, Device Authorization | Registered client of the service |
| `pdf2md-short` | Authorization Code, PKCE `S256` required | 60-second access tokens for the JWT expiry check |
| `pdf2md-machine` | Client Credentials | Application identity, also with a DPoP-bound token |
| `pdf2md-introspection` | none | Introspection client of the service |
| `pdf2md-assertion` | Client Credentials | `private_key_jwt` client and introspection client |

Every client receives the default client scope `pdf2md-resource`. Its
[audience mappers](https://www.keycloak.org/docs/latest/server_admin/#_audience)
add the resource URI `https://pdf2md.example.test/` and the two introspection
clients to `aud` of every access token, for every grant. The default `roles`,
`profile` and `email` scopes are not assigned, so access tokens carry no user
attributes.

Keycloak's sign-in, device verification and consent pages are HTML forms. The
harness and the Rust test submit those forms for the synthetic users, without
a browser. This is test-client automation; the service's own pages do not
collect passwords.

The opt-in Rust test `tests/live_keycloak.rs` checks:

- Authorization Code with PKCE through `/oauth/login` and `/oauth/callback`,
  including the cookie-bound state and the RFC 9207 `iss` parameter.
- That the result page shows no refresh token, and that no HTTP route redeems
  a device code or refresh token.
- Device Authorization through the library client, including
  `authorization_pending` before a second user approves the code.
- Refresh Token through the library client, including rejection of a used
  refresh token.
- Client Credentials through the library client, as a separate workspace.
- `private_key_jwt`: Client Credentials and introspection authenticated with a
  signed assertion instead of a shared secret.
- DPoP: a token that Keycloak bound to a key is accepted over HTTP with a fresh
  proof from that key, and refused as a Bearer token, without a proof, with a
  replayed proof, with another key's proof and with a proof made for another
  token. Local JWT validation confirms the same binding from `cnf.jkt`.
- Both validators with the `keycloak` token profile, configured scopes,
  private-workspace history and PDF access, rejection of ID and refresh
  tokens, immediate revocation through introspection, and JWT expiry. Local JWT
  verification does not establish immediate token revocation.

The test uses a generated trusted CA; TLS certificate verification remains
enabled.

Set `PDF2MD_CARGO_PROFILE` to select a separate Cargo profile inherited from
`dev` for this harness. Both its build and test invocations use that profile.
`PDF2MD_LIVE_KEYCLOAK_TEST_EXECUTABLE` selects a verified prebuilt test
executable. A provider-only smoke test can be run with
`PDF2MD_KEYCLOAK_SKIP_RUST=1`. This explicitly skips Rust acceptance and is not
equivalent to the full test.

## Provider configuration

For operator configuration, use the service's `[auth.oidc]` issuer (the realm
URL, `https://HOST/realms/REALM`), audience, validation method,
`token_profile = "keycloak"` and runtime secret references; see
[authentication](../../docs/authentication.md#token-profiles). Keycloak 26.8.2
behaves as follows, and the harness configures the realm accordingly:

- Access, refresh and ID tokens are JWTs with the header type `JWT`, signed by
  the same realm. The `typ` claim names the token class (`Bearer`, `DPoP`,
  `Refresh`, `ID`), so the `keycloak` profile requires `Bearer`, or `DPoP`
  together with `cnf.jkt`. The client is in `azp`.
- Introspection answers only for a client named in the token's `aud`, and
  reports refresh and ID tokens as active to the client they were issued to.
  Add the introspection client to `aud` with an audience mapper, and keep it
  separate from the clients that obtain tokens.
- `aud` is set by audience mappers, for every grant including Client
  Credentials, so `additional_audiences` is not needed. The RFC 8707 `resource`
  parameter is accepted and has no effect unless a Keycloak resource-indicator
  feature is enabled.
- A client's required PKCE method also applies to its device authorization
  request, which carries no challenge. Leave the method unset on a client that
  uses Device Authorization through this service; the registered client always
  sends `S256` for Authorization Code.
- Device Authorization shows a consent page, and the token endpoint answers
  `slow_down` to polls within the advertised interval.
- A used refresh token is rejected only when the realm revokes refresh tokens
  (`revokeRefreshToken` with `refreshTokenMaxReuse = 0`).
- A loopback redirect URI matches any port
  ([RFC 8252 section 7.3](https://www.rfc-editor.org/rfc/rfc8252#section-7.3)).

Register clients explicitly; this integration does not depend on Dynamic
Client Registration.

### Signed client assertions and DPoP

For `private_key_jwt`, the harness generates an RSA key and a self-signed
certificate with OpenSSL and registers the certificate with the
`pdf2md-assertion` client, whose client authenticator is **Signed JWT**
(`client-jwt`). See
[Client authentication with a signed assertion](../../docs/authentication.md#client-authentication-with-a-signed-assertion)
for the service configuration. The assertion uses the client ID as issuer and
subject, as RFC 7523 requires, and the realm's JWKS never lists the client
key; the harness fails if it does.

For DPoP, the test requests a Client Credentials token with a proof for
Keycloak's token endpoint. Keycloak writes the key binding into the token
(`cnf.jkt`, `typ` `DPoP`) and into the introspection response, so both
validators can confirm it; see
[DPoP-bound access tokens](../../docs/authentication.md#dpop-bound-access-tokens).

References:

- [Keycloak server administration](https://www.keycloak.org/docs/latest/server_admin/)
- [Keycloak securing applications with OIDC](https://www.keycloak.org/securing-apps/oidc-layers)
- [Running Keycloak in a container](https://www.keycloak.org/server/containers)
- [OAuth token introspection](https://www.rfc-editor.org/rfc/rfc7662.html)
- [JWT client authentication](https://www.rfc-editor.org/rfc/rfc7523.html)
- [DPoP](https://www.rfc-editor.org/rfc/rfc9449.html)

Passing this harness establishes local provider and library-boundary evidence.
It does not establish hosted CI, Kubernetes deployment, or MCP-client acceptance.

The same harness exercises the HTTP listener with real tokens in both
validation modes, including upload/conversion permissions, job/PDF isolation,
revocation, expiry, and recovery of previously accepted queued work. For
image-level Kubernetes acceptance, use `python3 scripts/test-http-oidc.py IMAGE`;
see [HTTP API validation](../../docs/http-api.md#validation).
