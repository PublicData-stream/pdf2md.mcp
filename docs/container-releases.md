# Container Releases

## Image promotion

The configured runtime image name is
`ghcr.io/publicdata-stream/pdf2md.mcp`.
Publication promotes the exact AMD64 and ARM64 images built and checked by the
canonical GitHub Actions workflow. It does not rebuild the application after
those checks. This guide defines the public image-promotion contract referenced
by the SLSA provenance `buildType`.

## Eligible source tags

Release tags must be annotated Git tags that point directly to a commit on
`main`'s history. The tag must match one of these forms exactly:

| Tag | GitHub release state | Cargo package versions |
| --- | --- | --- |
| `X.Y.Z` | Published stable Release | Exactly `X.Y.Z` |
| `X.Y.Z-beta.N` | Published GitHub prerelease, where `N` is at least 1 | Exactly `X.Y.Z-beta.N` |
| `X.Y.Z-build.sha8` | No GitHub Release; publication starts when this tag is created | `X.Y.Z` |

`X`, `Y`, and `Z` are non-negative decimal integers without leading zeroes,
except for zero itself. Beta numbers start at one and have no leading zeroes.
`sha8` is the first eight lowercase hexadecimal characters of the tagged
commit. A `v` prefix, additional prerelease suffix, lightweight tag, tag that
does not point directly to a commit, or mismatch in either Cargo package
version is rejected. Both `pdf2md-mcp` and `pdf2md-obscura-worker` package
versions are checked at the tagged commit.

Stable and beta publication is triggered by publishing the corresponding
GitHub Release. Build-candidate publication is triggered only when a matching
tag is newly created. An existing eligible tag, including a historical tag,
can be retried with **Actions → Publish runtime images → Run workflow** from
`main`, supplying its exact name in `release_tag`.

## Exact tested-image gate

Before publishing, the workflow selects the newest canonical
`.github/workflows/check.yml` run for a canonical `main` push at the exact tag
commit. That run and its `CI summary` must be completed successfully, and its
AMD64 and ARM64 runtime image artifacts must be present, unexpired, and tied to
successful image-build jobs in that same run. The artifacts are retained for
30 days. An in-progress, failed, missing, expired, or otherwise unverifiable
run fails closed. Re-run CI for the original commit and then retry publication;
the publication workflow never substitutes a rebuild for unavailable tested
images.

Publication is serialized, but GitHub Actions allows one running and one
pending execution in a concurrency group. A newer request can replace a
pending request. If that happens, manually retry the original eligible tag.
GHCR updates several tags and manifests without a registry-wide transaction;
a failure can leave a partial publication. The workflow records partial
results for diagnosis and retry. It does not destructively overwrite
unverifiable conflicting tags.
If rerunning CI produces different image contents after a partial publication,
the conflict remains an error: use a new eligible version or build-candidate
tag rather than moving an existing release tag.

## Image names and aliases

For each eligible version tag, publication creates these canonical references:

| Reference suffix | Contents |
| --- | --- |
| `TAG-alpine-musl-amd64` | `linux/amd64` runtime image |
| `TAG-alpine-musl-arm64` | `linux/arm64` runtime image |
| `TAG` | Multi-platform index for AMD64 and ARM64 |
| `TAG-alpine-musl` | The same multi-platform index |

For example, a stable `1.2.3` release publishes
`1.2.3-alpine-musl-amd64`, `1.2.3-alpine-musl-arm64`, `1.2.3`, and
`1.2.3-alpine-musl`. Beta and build tags receive these versioned references
without moving aliases.

Stable releases may advance `latest`, `alpine-musl`, `MAJOR-alpine-musl`, and
`MAJOR-alpine-musl-amd64` / `MAJOR-alpine-musl-arm64` (for example,
`1-alpine-musl-amd64`). Alias movement is forward-only by semantic version.
When an existing alias cannot be verified or would conflict with a newer
release, promotion fails or preserves the newer version. No `main`, minor
version, or extra SHA tag is published. Consumers that need a fixed image
should use a digest reference, such as
`ghcr.io/publicdata-stream/pdf2md.mcp@sha256:...`. Workflow checks protect
canonical tags during promotion, but GHCR does not enforce their immutability.

## Provenance and software inventories

The GitHub-hosted workflow creates SLSA v1 provenance for each platform image
and the multi-platform index, and CycloneDX SBOM attestations for the platform
images and aggregate index through GitHub's API-backed attestation service,
with registry push disabled. Provenance describes image promotion, not an
independent build: it records the source tag and commit, CI run and attempt,
image-archive checksums, platform configuration digests, the trusted
publication implementation, and the actual publication workflow identity.
Platform and index digests are attested; configuration digests are recorded as
provenance fields, not attestation subjects. Signed attestation bundles are
retained as GitHub Actions workflow artifacts. `ghcr-publication-candidate`
contains the uploaded-image report and inventories, the three
`ghcr-attestation-*` artifacts contain signed bundles, and `ghcr-publication`
records final qualification and alias results. Evidence retention is 90 days;
partial reports remain available when a later phase fails.

Each platform SBOM combines the runtime image scan with a separately labelled
Cargo.lock source inventory. That inventory lists resolved source packages,
including optional and development packages; it is not a claim that every
listed package is linked into the runtime executable. The aggregate index SBOM
combines the platform SBOMs.

Verify a published image's SLSA provenance against the repository and expected
predicate type with GitHub CLI:

```sh
gh attestation verify \
  oci://ghcr.io/publicdata-stream/pdf2md.mcp@sha256:DIGEST \
  --repo PublicData-stream/pdf2md.mcp \
  --signer-workflow PublicData-stream/pdf2md.mcp/.github/workflows/publish-images.yml \
  --predicate-type https://slsa.dev/provenance/v1
```

Use `https://cyclonedx.org/bom` as the predicate type to verify its CycloneDX
SBOM attestation. Replace `DIGEST` with the digest from the published platform
image or multi-platform index. GHCR publication does not use Cosign, does not
push attestations as OCI referrers, and does not provide an independent rebuild
or a separate vulnerability-scan release gate.

## Package visibility and support boundary

GitHub Container Registry packages start private by default, including for a
public repository. An operator must make this package public in its GitHub
package settings. On a first publication, image upload can succeed while
anonymous verification fails because visibility is still private; make the
package public and retry the eligible tag.

Publishing stable image tags does not establish a security support window,
maintenance period, or backport commitment. See the [Security
Policy](../SECURITY.md) for the current support and vulnerability-reporting
boundary.

## Local publication checks

Run workflow lint, CI source validation, and the Python helper tests from the
repository root:

```sh
actionlint
python3 scripts/ci/check.py source
python3 -m unittest discover -s tests/scripts -p 'test_*.py'
```

The registry publication harness accepts only a disposable local registry and
synthetic two-architecture inputs. It uses temporary state and does not publish
to the project package:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-publication.py \
  REGISTRY_IMAGE@sha256:DIGEST
```

The existing Docker and optional Minikube runtime smoke checks remain separate
from publication verification; see
[`CONTRIBUTING.md`](../CONTRIBUTING.md#ci-coverage-and-reproduction). Passing
local checks does not establish hosted workflow, public registry, deployment,
or client acceptance.
