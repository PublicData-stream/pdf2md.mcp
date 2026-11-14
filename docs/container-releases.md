# Container Releases

## Image promotion v1

The configured runtime image name is
`ghcr.io/publicdata-stream/pdf2md.mcp`.
Publication promotes the exact AMD64 and ARM64 images built and checked by the
canonical GitHub Actions workflow. It does not rebuild the application after
those checks. This section defines the versioned promotion predicate type
`https://github.com/PublicData-stream/pdf2md.mcp/blob/main/docs/container-releases.md#image-promotion-v1`.

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
`main`, supplying its exact name in `release_tag`. After a publication workflow
repair reaches `main`, start a fresh manual dispatch from the repaired `main`;
rerunning an old publication run uses its old workflow revision. For example,
retry `0.1.0-build.350ff642` after the partial-rerun validation repair with:

```sh
gh workflow run publish-images.yml --ref main -f release_tag=0.1.0-build.350ff642
```

Keep the existing annotated tag and reuse its
retained, tested image artifacts. Matching canonical image digests are reused;
conflicting digests remain an error.

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

Partial CI reruns may retain successful image jobs from an earlier attempt.
GitHub can return these carried-forward executions under different job IDs and
attempt numbers. When multiple successful job records match an artifact's
creation window, the gate accepts them only when they share a positive runner
ID and identical start and completion timestamps. Different runners, different
windows, or missing runner identity remain ambiguous and fail closed. This
correlates GitHub execution metadata; it is not a direct artifact-to-job
identifier or independent provenance proof.

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

## Promotion attestations and software inventories

The GitHub-hosted workflow creates a signed image-promotion attestation and a
CycloneDX SBOM attestation for each platform image and the multi-platform index
through GitHub's API-backed attestation service, with registry push disabled.
The promotion predicate has these fields:

- `operation`: `promote-tested-images`.
- `source`: the release `tag`, source `revision`, and `tagObjectSha`.
- `target`: `amd64`, `arm64`, or `index`.
- `ci`: the selected producing CI run, attempt, and artifact information.
- `inputs`: the source Git URI and commit digest, and the relevant CI image
  archive URI and SHA-256 checksum for each platform represented by the target.
- `platformConfigDigests`: the configuration digests for both architectures.
- `publication`: `implementationRevision`, `workflowRef`, `workflowSha`, and
  `invocationId` for the publication workflow.

The platform manifest and index digests are attestation subjects; configuration
digests are predicate fields. This is a promotion attestation, not SLSA build
provenance. Its signed claims describe the publication workflow's checks and
inputs; signature verification does not independently verify the producing CI
run or rebuild the images.

Signed bundles are retained as GitHub Actions workflow artifacts.
`ghcr-publication-candidate` contains the uploaded-image report and inventories,
the three `ghcr-attestation-*` artifacts contain signed bundles, and
`ghcr-publication` records final qualification and alias results. For
compatibility, promotion predicate and bundle filenames retain `provenance`,
and publication report keys retain `provenance`. Evidence retention is 90 days;
partial reports remain available when a later phase fails.

Each platform SBOM combines the runtime image scan with a separately labelled
Cargo.lock source inventory. That inventory lists resolved source packages,
including optional and development packages; it is not a claim that every
listed package is linked into the runtime executable. The aggregate index SBOM
combines the platform SBOMs.

Each generated platform or index SBOM has a fresh UUID4 URN in `serialNumber`,
including when the same inputs are processed again. These are new composite
documents, so they do not reuse the scanner document's serial number. The
[pinned attestation action's CycloneDX detector](https://github.com/actions/attest/blob/1e69f48acb82d1966a394da916b4c1698aa569d6/src/sbom.ts)
requires `bomFormat`, `serialNumber`, and `specVersion`; passing that detector
does not establish complete CycloneDX schema validation.

Verify a published image's promotion attestation against the repository,
expected signer workflow, subject digest, and predicate type with GitHub CLI:

```sh
gh attestation verify \
  oci://ghcr.io/publicdata-stream/pdf2md.mcp@sha256:DIGEST \
  --repo PublicData-stream/pdf2md.mcp \
  --signer-workflow PublicData-stream/pdf2md.mcp/.github/workflows/publish-images.yml \
  --predicate-type https://github.com/PublicData-stream/pdf2md.mcp/blob/main/docs/container-releases.md#image-promotion-v1
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
