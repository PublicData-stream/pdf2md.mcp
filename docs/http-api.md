# HTTP API

Copy `examples/http.toml` to your own configuration and select `auth.mode =
"none_rw"` for anonymous uploads or use `examples/http-oauth.toml` for OAuth.
Start `pdf2md-mcp --config http.toml serve`. The untouched example is read-only. The default listener is
`127.0.0.1:8080`; use `serve --listen 0.0.0.0:8080` when a container network
must reach it. `/openapi.json` describes the API and `/docs` provides a bundled,
offline operation console. Its bearer-token field is held in browser memory.
Use a trusted TLS-terminating proxy when accessing the service across a network.
`/healthz` and `/readyz` provide health and readiness probes.

The default authentication mode is anonymous read-only. In `none_rw`, callers
share one writable workspace. OAuth2 uses bearer access tokens and isolates
workspaces by issuer and subject; it does not provide login or issue tokens.
Read operations require the configured read scope, and mutations require both
read and write scopes. See [authentication](authentication.md) for validation,
provider setup, and workspace boundaries.

## Operations

The generated OpenAPI document is the authoritative schema for request and
response fields. Main routes are:

| Route | Purpose |
| --- | --- |
| `POST /v1/documents` | Upload an `application/pdf` body or multipart `file`; returns an observation and optional automatic conversion job. |
| `POST /v1/acquisitions` | Submit JSON containing `url` for public HTTPS acquisition. |
| `GET /v1/status`, `GET /v1/history`, `GET /v1/conversions` | List workspace observations or conversions. |
| `POST /v1/documents/{id}/conversions` | Request a conversion, optionally with `pages` and `force`. |
| `GET /v1/conversions/{id}/manifest`, `/markdown`, `/assets/{name}`, `/bundle.zip` | Read an immutable conversion bundle. |
| `GET /v1/jobs`, `GET /v1/jobs/{id}` | Inspect durable jobs. |
| `POST /v1/jobs/{id}/cancel`, `/retry` | Cancel or retry a job. |
| `GET /v1/sources`, `POST /v1/sources/{id}/fetch` | List or fetch operator-published sources. |
| `GET /v1/schedules`, `PUT /v1/schedules/{source_id}` | Inspect or enable/disable schedules for published sources. |

List responses contain `items` and `next_cursor`; the default page size is 100
and the maximum is 1,000. Uploads return HTTP 201 with `observation` and
`conversion_job` (which can be null). An acquisition returns HTTP 202 with a
job. Jobs expose their ID, kind, status, relevant document, observation and
conversion IDs, error code, and timestamps. Retried jobs include `retry_of`. Automatic conversion follows
`conversion.enabled`, which defaults to true. JSON command submissions support an optional `Idempotency-Key` (1–128 printable
ASCII characters); repeating a key with different command parameters returns
409. Explicit retries create a linked job; an already active matching conversion
returns 409 for retry submissions. Ordinary conversion requests reuse matching
active or successful work. History is retained.

An upload can be submitted with:

```sh
curl --fail-with-body -H 'Content-Type: application/pdf' \
  --data-binary @document.pdf http://127.0.0.1:8080/v1/documents
```

Multipart uploads use `curl --fail-with-body -F file=@document.pdf
http://127.0.0.1:8080/v1/documents`. Use returned IDs in subsequent commands:

```sh
curl --fail-with-body http://127.0.0.1:8080/v1/jobs/JOB_ID
curl --fail-with-body -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: selected-pages-1' \
  --data '{"pages":"1-3","force":false}' \
  http://127.0.0.1:8080/v1/documents/DOCUMENT_ID/conversions
curl --fail-with-body -o bundle.zip \
  http://127.0.0.1:8080/v1/conversions/CONVERSION_ID/bundle.zip
curl --fail-with-body -X POST \
  http://127.0.0.1:8080/v1/sources/SOURCE_ID/fetch
curl --fail-with-body -X PUT -H 'Content-Type: application/json' \
  --data '{"enabled":true}' http://127.0.0.1:8080/v1/schedules/SOURCE_ID
```

For OAuth add `Authorization: Bearer ACCESS_TOKEN`; keep tokens out of shell
history, logs, and shared configuration. API callers cannot select workspace
paths, configure worker processes, or submit source definitions.

## Published sources and schedules

`http.published_sources` defaults to an empty list. An operator explicitly adds
configured source IDs before callers can use these source and schedule routes.
OAuth callers need the configured operate scope (`pdf2md:operate` by
default) for source execution and schedule changes, in addition to read and write
scopes. Source and schedule listing require the read scope;
no-auth writable callers share this authority for published sources. Source
credentials and intervals remain operator configuration, not caller input.
Enabling a schedule triggers an immediate fetch and then uses its configured
interval. The grant is durable: no access token is retained, and token expiry or
revocation does not stop an already enabled schedule. Disable the schedule or
remove the source from the published policy to stop that authority. With the server stopped, trusted operators can inspect or disable grants:

```sh
pdf2md-mcp --data-dir ./pdf2md-mcp-data --workspace shared schedules list
pdf2md-mcp --data-dir ./pdf2md-mcp-data --workspace shared schedules disable SOURCE_ID
```

For a private workspace, replace `shared` with its initialized workspace UUID.

Queued jobs survive restart. In-flight jobs interrupted by restart require an
explicit retry. A configuration or source fingerprint mismatch pauses a schedule
and interrupts a queued fetch instead of silently executing changed policy.
A completed acquisition does not by itself establish successful conversion;
inspect the corresponding conversion job and history.

## Limits and deployment

The upload limit inherits the configured acquisition limit (1 GiB by default).
JSON bodies are limited to 64 KiB. HTTP defaults cap jobs at 100 per workspace
and 1,000 total and allow four concurrent downloads. `[http]` accepts `bind`,
`published_sources`, `per_workspace_jobs`, `total_jobs`, and `downloads`.
Conversion and acquisition retain their own resource limits. The service is a
single-host writer; use one replica and do not share its data root with another
writer. See the [Kubernetes example](../examples/kubernetes/README.md) and
[security policy](../SECURITY.md). These controls do not provide an OS sandbox
or per-user disk quotas.

## Validation

Run `python3 scripts/test-http.py IMAGE --minikube` for disposable Docker and
anonymous RW Kubernetes workflows, including persistence across restart. Run
`python3 scripts/test-authelia.py` for real opaque/JWT HTTP and library token,
scope, isolation, revocation, expiry, and accepted-job recovery checks.
`python3 scripts/test-http-oidc.py IMAGE` exercises real OIDC inside a disposable
Minikube deployment. Browser-source upstream acceptance is reported separately
from authentication and conversion assertions. These harnesses keep generated
credentials and configuration under `/tmp` and remove their own resources.
