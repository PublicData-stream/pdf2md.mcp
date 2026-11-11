# Authelia compatibility test

Run the disposable integration harness from the repository root:

```sh
export CARGO_TARGET_DIR=/tmp/rust/target
export TMPDIR=/tmp
python3 scripts/test-authelia.py
```

Requirements are a reachable local Docker daemon, OpenSSL, Python 3, and the
project's Rust toolchain. Select your intended local Docker context before
running the script. The harness uses Authelia 4.39.28 pinned to its published
image digest, binds its TLS listener to loopback, and removes the container and
temporary directory after success or failure. All generated provider storage,
certificates, synthetic credentials, and token fixtures live under `/tmp`.

The harness registers two confidential Authorization Code clients requiring
PKCE S256, one using opaque access tokens and the other using RS256 JWT access
tokens. Two synthetic users log in and explicitly consent through the pinned
provider's login and consent HTTP endpoints. This is test-client automation;
the application does not expose browser login or callback endpoints.

The opt-in Rust test checks both validators, configured scopes, private-workspace
history and PDF access, rejection of ID/refresh tokens, immediate opaque-token
revocation through introspection, and JWT expiry. Local JWT verification does
not establish immediate token revocation. The test uses a generated trusted CA;
TLS certificate verification remains enabled.

Set `PDF2MD_CARGO_PROFILE` to select a separate Cargo profile inherited from
`dev` for this harness. Both its build and test invocations use that profile.

A provider-only smoke test can be run with `PDF2MD_AUTHELIA_SKIP_RUST=1`. This
explicitly skips Rust acceptance and is not equivalent to the full test.

For operator configuration, use the service's `[auth.oidc]` issuer, audience,
validation method, and runtime secret references. For introspection, set
`access_token_prefix = "authelia_at_"`: Authelia omits `token_type` from its
introspection response, so this explicit prefix restricts validation to its
access-token format before remote activity and claim checks. Refresh and ID
tokens remain rejected. For JWT validation, set `jwt_scope_claim = "scp"`:
Authelia 4.39.28 emits the granted scopes as an `scp` array. The generic default
uses the standard `scope` claim; the service does not merge claims or
automatically fall back between them. Configure the same resource
URI in Authelia's client `audience` list and permit the `pdf2md:read` and
`pdf2md:write` custom scopes. Keep access-token and ID-token audiences distinct.
Register clients explicitly; this integration does not depend on Dynamic Client
Registration.

References:

- [Authelia 4.39.28 release](https://github.com/authelia/authelia/releases/tag/v4.39.28)
- [Authelia OpenID Connect client configuration](https://www.authelia.com/configuration/identity-providers/openid-connect/clients/)
- [OAuth token introspection](https://www.rfc-editor.org/rfc/rfc7662.html)
- [JWT access-token profile](https://www.rfc-editor.org/rfc/rfc9068.html)

Passing this harness establishes local provider and library-boundary evidence.
It does not establish hosted CI, Kubernetes deployment, or MCP-client acceptance.

The same harness exercises the HTTP listener with both opaque and JWT tokens,
including upload/conversion permissions, job/PDF isolation, revocation, expiry,
and recovery of previously accepted queued work. For image-level Kubernetes
acceptance, use `python3 scripts/test-http-oidc.py IMAGE`; see
[HTTP API validation](../../docs/http-api.md#validation).
