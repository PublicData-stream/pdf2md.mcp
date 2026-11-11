# HTTP deployment example

`http.yaml` creates a single-replica HTTP Deployment, Service, ConfigMap and
PVC. Replace the image and storage size for your environment before applying
it. The `Recreate` strategy and single replica respect the single-writer data
root; do not scale it horizontally or share its volume with another writer.
The config file is mounted read-only with `subPath`, presenting a regular file
to the configuration loader. ConfigMap changes require a rollout. The process runs as UID/GID
10001. The volume must permit that user to write; `fsGroup` support depends on the storage
provider. The Service is internal by default. Terminate TLS at a trusted ingress
and restrict network access according to your authentication mode.

The example defaults to anonymous read-only access. For OAuth, replace the
ConfigMap TOML with the settings in `../http-oauth.toml`, using your provider's
issuer, audience, and validation mode. For introspection, provision a Secret
named `pdf2md-oidc` with the `client-secret` key using your secret manager, and
apply `http-oauth-patch.yaml` to the Deployment. Never put credentials in the
ConfigMap or commit them. JWT validation does not need the client secret.
See [authentication](../../docs/authentication.md) for provider configuration
and [HTTP API](../../docs/http-api.md) for permissions and scheduling.

Back up the entire data volume together with PostgreSQL metadata, if configured,
with writers stopped. This example does not establish production capacity,
network isolation, or provider acceptance.
