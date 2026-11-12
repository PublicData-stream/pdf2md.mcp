#!/usr/bin/env python3
"""Promote verified CI Docker archives without rebuilding their contents."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from types import SimpleNamespace
import urllib.error
import urllib.parse
import urllib.request
import uuid

SPEC = importlib.util.spec_from_file_location("publication_artifacts", Path(__file__).with_name("artifacts.py"))
artifacts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifacts)
IMAGE = "ghcr.io/publicdata-stream/pdf2md.mcp"
ARCHES = ("amd64", "arm64")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST_TYPES = {MANIFEST, "application/vnd.docker.distribution.manifest.v2+json"}
INDEX_TYPES = {INDEX, "application/vnd.docker.distribution.manifest.list.v2+json"}
LIMIT = 16 * 1024 * 1024


class PublicationError(ValueError):
    """A fixed, non-secret diagnostic category safe for publication reports."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def encoded(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def sha(blob):
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def read_json(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > LIMIT:
        raise PublicationError("invalid_metadata_file")
    return json.loads(path.read_text())


def write_json(path, document):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_suffix(path.suffix + ".pending")
    pending.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    pending.replace(path)


def validate_plan(plan):
    if (plan.get("schema_version") != 1 or plan.get("repository") != "PublicData-stream/pdf2md.mcp"
            or plan.get("image") != IMAGE or not re.fullmatch(r"[0-9a-f]{40}", plan.get("revision", ""))
            or not re.fullmatch(r"[0-9a-f]{40}", plan.get("tag_object_sha", ""))):
        raise PublicationError("invalid_publication_plan")
    number = r"(?:0|[1-9][0-9]*)"
    base = rf"{number}\.{number}\.{number}"
    tag = plan.get("tag", "")
    patterns = {"stable": base, "beta": base + r"-beta\.[1-9][0-9]*",
                "build": base + r"-build\.[0-9a-f]{8}"}
    if (len(tag) + len("-alpine-musl-arm64") > 128
            or plan.get("version") != tag or plan.get("kind") not in patterns
            or not re.fullmatch(patterns[plan["kind"]], tag)
            or (plan["kind"] == "build" and not plan["revision"].startswith(tag.rsplit(".", 1)[1]))):
        raise PublicationError("invalid_publication_version")
    return plan


def selected_image(plan, test_image=None):
    if test_image:
        if not re.fullmatch(r"(?:localhost|127\.0\.0\.1):[1-9][0-9]{0,4}/[a-z0-9][a-z0-9._/-]*", test_image):
            raise PublicationError("invalid_test_registry")
        if int(test_image.split(":", 1)[1].split("/", 1)[0]) > 65535:
            raise PublicationError("invalid_test_registry")
        return test_image
    return plan["image"]


class Registry:
    """Small bounded Distribution client; Docker handles actual layer uploads."""
    def __init__(self, image, anonymous=False, writable=False):
        self.host, self.repository = image.split("/", 1)
        self.local = bool(re.fullmatch(r"(?:localhost|127\.0\.0\.1):[0-9]+", self.host))
        if not self.local and image != IMAGE:
            raise PublicationError("unexpected_registry")
        self.base = ("http://" if self.local else "https://") + self.host
        self.anonymous = anonymous
        self.writable = writable
        self.token = None
        self.opener = urllib.request.build_opener(NoRedirect())

    def _read(self, request):
        with self.opener.open(request, timeout=30) as response:
            blob = response.read(LIMIT + 1)
            if len(blob) > LIMIT:
                raise PublicationError("registry_metadata_too_large")
            return blob, response.headers

    def _blob_redirect(self, destination):
        # Registry blob redirects use signed CDN URLs. Never carry registry
        # Authorization to a CDN, and never allow redirects for token/manifests.
        for _ in range(4):
            parsed = urllib.parse.urlsplit(destination)
            host = parsed.hostname or ""
            if (parsed.scheme != "https" or parsed.username is not None or parsed.password is not None
                    or parsed.port not in (None, 443) or parsed.fragment
                    or not (host == "pkg-containers.githubusercontent.com"
                            or host.endswith(".blob.core.windows.net"))):
                raise PublicationError("registry_blob_redirect_rejected")
            try:
                return self._read(urllib.request.Request(destination))
            except urllib.error.HTTPError as error:
                error.close()
                if error.code not in (301, 302, 303, 307, 308) or not error.headers.get("Location"):
                    raise PublicationError("registry_blob_download_failed") from error
                destination = urllib.parse.urljoin(destination, error.headers["Location"])
        raise PublicationError("registry_blob_redirect_limit")

    def _authorize(self, challenge):
        fields = dict(re.findall(r'([a-z]+)="([^"\r\n]*)"', challenge or ""))
        if (self.local or not (challenge or "").startswith("Bearer ")
                or fields.get("realm") != "https://ghcr.io/token"
                or fields.get("service") != "ghcr.io"):
            raise PublicationError("registry_auth_challenge_rejected")
        scope = "repository:" + self.repository + (":pull,push" if self.writable else ":pull")
        request = urllib.request.Request(fields["realm"] + "?" + urllib.parse.urlencode({
            "service": "ghcr.io", "scope": scope}))
        if not self.anonymous:
            token = os.environ.get("GH_TOKEN", "")
            actor = os.environ.get("GITHUB_ACTOR", "")
            if not token or not actor:
                raise PublicationError("registry_credentials_missing")
            request.add_header("Authorization", "Basic " + base64.b64encode((actor + ":" + token).encode()).decode())
        try:
            blob, _ = self._read(request)
        except urllib.error.HTTPError as error:
            error.close()
            raise PublicationError("anonymous_access_unavailable" if self.anonymous else "registry_auth_failed") from error
        result = json.loads(blob)
        self.token = result.get("token", result.get("access_token"))
        if not isinstance(self.token, str) or not self.token or "\n" in self.token or "\r" in self.token:
            raise PublicationError("registry_token_invalid")

    def request(self, section, reference, method="GET", blob=None, media=None, missing=False):
        if section not in {"manifests", "blobs"} or not re.fullmatch(r"[A-Za-z0-9_.:-]+", reference):
            raise PublicationError("invalid_registry_reference")
        if method != "GET" and not self.writable:
            raise PublicationError("registry_write_not_enabled")
        url = self.base + "/v2/" + self.repository + "/" + section + "/" + reference
        for attempt in range(2):
            request = urllib.request.Request(url, data=blob, method=method)
            request.add_header("Accept", ", ".join(sorted(MANIFEST_TYPES | INDEX_TYPES)))
            if media:
                request.add_header("Content-Type", media)
            if self.token:
                request.add_header("Authorization", "Bearer " + self.token)
            try:
                return self._read(request)
            except urllib.error.HTTPError as error:
                error.close()
                if error.code in (301, 302, 303, 307, 308):
                    if method != "GET" or section != "blobs" or not error.headers.get("Location"):
                        raise PublicationError("registry_redirect_rejected") from error
                    return self._blob_redirect(urllib.parse.urljoin(url, error.headers["Location"]))
                if error.code == 404 and missing:
                    return None
                if error.code == 401 and attempt == 0:
                    self._authorize(error.headers.get("WWW-Authenticate"))
                    continue
                raise PublicationError("anonymous_access_unavailable" if self.anonymous else "registry_request_failed") from error
        raise PublicationError("registry_auth_failed")

    def manifest(self, reference, missing=False):
        result = self.request("manifests", reference, missing=missing)
        if result is None:
            return None
        blob, headers = result
        digest = sha(blob)
        if headers.get("Docker-Content-Digest", digest) != digest:
            raise PublicationError("registry_manifest_digest_mismatch")
        if DIGEST.fullmatch(reference) and reference != digest:
            raise PublicationError("registry_manifest_digest_mismatch")
        document = json.loads(blob)
        if document.get("schemaVersion") != 2 or document.get("mediaType") not in MANIFEST_TYPES | INDEX_TYPES:
            raise PublicationError("registry_manifest_invalid")
        return {"blob": blob, "document": document, "digest": digest}

    def config(self, manifest):
        document = manifest["document"]
        if document.get("mediaType") not in MANIFEST_TYPES:
            raise PublicationError("platform_manifest_required")
        reference = document.get("config", {}).get("digest", "")
        if not DIGEST.fullmatch(reference):
            raise PublicationError("registry_config_invalid")
        blob, _ = self.request("blobs", reference)
        if sha(blob) != reference:
            raise PublicationError("registry_config_digest_mismatch")
        config = json.loads(blob)
        if config.get("os") != "linux" or config.get("architecture") not in ARCHES:
            raise PublicationError("registry_platform_invalid")
        return reference, "linux/" + config["architecture"]

    def put(self, reference, blob, media):
        self.request("manifests", reference, method="PUT", blob=blob, media=media)
        result = self.manifest(reference)
        if result["digest"] != sha(blob):
            raise PublicationError("registry_write_readback_mismatch")
        return result


def checked_archives(plan, directory):
    """Validate both archives completely before Docker load or registry mutation."""
    values = {}
    for arch in ARCHES:
        base = Path(directory) / arch
        for name in ("manifest.json", "image.tar"):
            if (base / name).is_symlink() or not (base / name).is_file():
                raise PublicationError("runtime_artifact_missing")
        metadata = read_json(base / "manifest.json")
        expected_tag = "pdf2md-mcp:ci-" + plan["revision"] + "-" + arch
        if metadata.get("image") != expected_tag:
            raise PublicationError("runtime_artifact_tag_mismatch")
        artifacts.read_manifest(SimpleNamespace(input=base, commit=plan["revision"], arch=arch), "image")
        expected = {"platform": "linux/" + arch, "config_digest": metadata.get("config_digest")}
        if (not DIGEST.fullmatch(expected["config_digest"] or "")
                or artifacts.archive_image(base / "image.tar", expected_tag) != expected
                or metadata.get("platform") != expected["platform"]):
            raise PublicationError("runtime_artifact_identity_mismatch")
        values[arch] = metadata
    return values


def docker(*arguments, env=None):
    try:
        subprocess.run(["docker", *arguments], check=True, capture_output=True, timeout=1200, env=env)
    except (subprocess.SubprocessError, OSError) as error:
        raise PublicationError("docker_operation_failed") from error


def docker_endpoint():
    # An empty CLI config has no currentContext. Resolve the selected endpoint
    # first so credential isolation does not silently switch Docker daemons.
    endpoint = os.environ.get("DOCKER_HOST")
    if not endpoint or os.environ.get("DOCKER_CONTEXT"):
        try:
            result = subprocess.run(["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
                                    check=True, capture_output=True, text=True, timeout=30)
        except (subprocess.SubprocessError, OSError) as error:
            raise PublicationError("docker_endpoint_resolution_failed") from error
        endpoint = result.stdout.strip()
    if not endpoint.startswith("unix://") or "\n" in endpoint or "\r" in endpoint:
        raise PublicationError("anonymous_pull_requires_local_daemon")
    return endpoint


def initial_report(plan, image, metadata):
    return {"schema_version": 1, "image": image,
            "source": {key: plan[key] for key in ("tag", "kind", "revision", "tag_object_sha", "ci")},
            "platforms": {arch: {key: metadata[arch][key] for key in (
                "config_digest", "platform", "archive_sha256")} for arch in ARCHES},
            "index_digest": None, "tags": [plan["tag"], plan["tag"] + "-alpine-musl"],
            "aliases": {}, "status": "validated"}


def validated_report(plan, image, output):
    report = read_json(Path(output) / "report.json")
    expected = {key: plan[key] for key in ("tag", "kind", "revision", "tag_object_sha", "ci")}
    if report.get("schema_version") != 1 or report.get("image") != image or report.get("source") != expected:
        raise PublicationError("publication_report_identity_mismatch")
    return report


def validate(plan, directory, output, image):
    metadata = checked_archives(plan, directory)
    for arch in ARCHES:
        docker("load", "--input", str(Path(directory) / arch / "image.tar"))
        observed = artifacts.inspect_image(metadata[arch]["image"])
        if observed != {key: metadata[arch][key] for key in ("platform", "config_digest")}:
            raise PublicationError("loaded_runtime_identity_mismatch")
    report_path = Path(output) / "report.json"
    if report_path.exists():
        report = validated_report(plan, image, output)
        for arch in ARCHES:
            for key in ("config_digest", "platform", "archive_sha256"):
                if report["platforms"][arch].get(key) != metadata[arch][key]:
                    raise PublicationError("publication_report_artifact_mismatch")
        report.pop("error_category", None)
    else:
        report = initial_report(plan, image, metadata)
    write_json(report_path, report)
    return report


def platform_tag(plan, arch):
    return plan["tag"] + "-alpine-musl-" + arch


def index_document(plan, platforms):
    return {"schemaVersion": 2, "mediaType": INDEX,
            "annotations": {"org.opencontainers.image.version": plan["tag"],
                            "org.opencontainers.image.revision": plan["revision"],
                            "org.opencontainers.image.source": "https://github.com/PublicData-stream/pdf2md.mcp"},
            "manifests": [platforms[arch]["descriptor"] for arch in ARCHES]}


def verify_platform(registry, manifest, expected, arch):
    if registry.config(manifest) != (expected["config_digest"], "linux/" + arch):
        raise PublicationError("canonical_platform_conflict")
    prior = expected.get("digest")
    if prior is not None and manifest["digest"] != prior:
        raise PublicationError("canonical_manifest_conflict")


def publish(plan, directory, output, image, registry=None):
    report = validate(plan, directory, output, image)
    registry = registry or Registry(image, writable=True)
    # Detect every existing canonical collision before starting a partial upload.
    existing = {}
    for arch in ARCHES:
        tag = platform_tag(plan, arch)
        existing[arch] = registry.manifest(tag, missing=True)
        if existing[arch]:
            verify_platform(registry, existing[arch], report["platforms"][arch], arch)
    for tag in report["tags"]:
        current = registry.manifest(tag, missing=True)
        if current:
            doc = current["document"]
            if (any(existing[arch] is None for arch in ARCHES)
                    or doc != index_document(plan, {
                        arch: {"descriptor": {"mediaType": existing[arch]["document"]["mediaType"],
                            "digest": existing[arch]["digest"], "size": len(existing[arch]["blob"]),
                            "platform": {"os": "linux", "architecture": arch}}} for arch in ARCHES})):
                raise PublicationError("canonical_index_conflict")
    for arch in ARCHES:
        tag = platform_tag(plan, arch)
        if existing[arch] is None:
            local_tag = "pdf2md-mcp:ci-" + plan["revision"] + "-" + arch
            remote_tag = image + ":" + tag
            # Another writer must not have filled the tag after the preflight.
            if registry.manifest(tag, missing=True) is not None:
                raise PublicationError("canonical_tag_changed")
            docker("tag", local_tag, remote_tag)
            docker("push", "--platform", "linux/" + arch, remote_tag)
        manifest = registry.manifest(tag)
        entry = report["platforms"][arch]
        verify_platform(registry, manifest, entry, arch)
        entry.update({"digest": manifest["digest"], "tag": tag,
                      "descriptor": {"mediaType": manifest["document"]["mediaType"],
                          "digest": manifest["digest"], "size": len(manifest["blob"]),
                          "platform": {"os": "linux", "architecture": arch}}})
        (Path(output) / ("platform-" + arch + ".json")).write_bytes(manifest["blob"])
        write_json(Path(output) / "report.json", report)
    blob = encoded(index_document(plan, report["platforms"]))
    for tag in report["tags"]:
        current = registry.manifest(tag, missing=True)
        if current and current["blob"] != blob:
            raise PublicationError("canonical_index_conflict")
        if current is None:
            registry.put(tag, blob, INDEX)
        report["index_digest"] = sha(blob)
        write_json(Path(output) / "report.json", report)
    (Path(output) / "index.json").write_bytes(blob)
    report["status"] = "published"
    write_json(Path(output) / "report.json", report)
    return report


def verify(plan, output, image, anonymous=False, registry=None, pull=True):
    report = validated_report(plan, image, output)
    registry = registry or Registry(image, anonymous=anonymous)
    expected_index = index_document(plan, report["platforms"])
    for arch in ARCHES:
        entry = report["platforms"][arch]
        if not DIGEST.fullmatch(entry.get("digest", "")):
            raise PublicationError("published_platform_missing")
        manifest = registry.manifest(entry["digest"])
        verify_platform(registry, manifest, entry, arch)
        if registry.manifest(platform_tag(plan, arch))["digest"] != entry["digest"]:
            raise PublicationError("canonical_tag_changed")
    for tag in report["tags"]:
        manifest = registry.manifest(tag)
        if manifest["digest"] != report["index_digest"] or manifest["document"] != expected_index:
            raise PublicationError("canonical_index_conflict")
    if pull:
        # A separate config prevents inherited login helpers or credentials from
        # turning an anonymous-access check into an authenticated pull.
        with tempfile.TemporaryDirectory(prefix="pdf2md-pull-", dir="/tmp") as temporary:
            environment = dict(os.environ, DOCKER_CONFIG=temporary, DOCKER_HOST=docker_endpoint())
            environment.pop("DOCKER_CONTEXT", None)
            (Path(temporary) / "config.json").write_text('{"auths":{}}\n')
            if not anonymous:
                raise PublicationError("full_pull_requires_anonymous_mode")
            for arch in ARCHES:
                entry = report["platforms"][arch]
                reference = image + "@" + entry["digest"]
                docker("--config", temporary, "pull", "--platform", "linux/" + arch, reference, env=environment)
                # Digest-only pulls have no RepoTags in docker save metadata.
                # Give this exact digest a disposable tag before reusing the
                # archive validator, then remove only that temporary reference.
                inspection_tag = "pdf2md-publication-verify:" + uuid.uuid4().hex
                docker("--config", temporary, "tag", reference, inspection_tag, env=environment)
                try:
                    observed = artifacts.inspect_image(inspection_tag)
                    if observed != {key: entry[key] for key in ("platform", "config_digest")}:
                        raise PublicationError("pulled_runtime_identity_mismatch")
                finally:
                    docker("--config", temporary, "image", "rm", inspection_tag, env=environment)
    report["anonymous_verified"] = anonymous
    report["status"] = "verified"
    write_json(Path(output) / "report.json", report)
    return report


def stable_version(tag):
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", tag):
        raise PublicationError("existing_alias_version_unverifiable")
    return tuple(map(int, tag.split(".")))


def alias_snapshot(registry, alias, major=None):
    current = registry.manifest(alias, missing=True)
    if current is None:
        return None, None
    doc = current["document"]
    version = doc.get("annotations", {}).get("org.opencontainers.image.version", "")
    parsed = stable_version(version)
    if major is not None and parsed[0] != major:
        raise PublicationError("existing_alias_version_unverifiable")
    canonical = registry.manifest(version)
    if canonical["digest"] != current["digest"] or doc.get("mediaType") not in INDEX_TYPES:
        raise PublicationError("existing_alias_version_unverifiable")
    children = doc.get("manifests", [])
    if (len(children) != 2 or {row.get("platform", {}).get("architecture") for row in children} != set(ARCHES)
            or any(row.get("platform", {}).get("os") != "linux" for row in children)):
        raise PublicationError("existing_alias_version_unverifiable")
    return current, parsed


def aliases(plan, output, image, registry=None):
    report = validated_report(plan, image, output)
    if not report.get("anonymous_verified"):
        raise PublicationError("anonymous_verification_required")
    if plan["kind"] != "stable":
        return report
    registry = registry or Registry(image, writable=True)
    # Re-read canonical inputs before moving any mutable reference.
    verify(plan, output, image, registry=registry, anonymous=True, pull=False)
    version = stable_version(plan["tag"])
    major = str(version[0])
    index_blob = (Path(output) / "index.json").read_bytes()
    if sha(index_blob) != report["index_digest"]:
        raise PublicationError("saved_index_digest_mismatch")
    snapshots = {}
    targets = {}
    for alias, required_major in (("latest", None), ("alpine-musl", None), (major + "-alpine-musl", version[0])):
        current, prior_version = alias_snapshot(registry, alias, required_major)
        snapshots[alias] = None if current is None else current["digest"]
        if prior_version is not None and prior_version > version:
            report["aliases"][alias] = {"digest": current["digest"], "status": "newer_release_preserved"}
            continue
        targets[alias] = (index_blob, INDEX, report["index_digest"])
    major_alias = major + "-alpine-musl"
    if major_alias in targets:
        for arch in ARCHES:
            alias = major_alias + "-" + arch
            current = registry.manifest(alias, missing=True)
            snapshots[alias] = None if current is None else current["digest"]
            # Platform alias must agree with the current major index. A partial
            # prior update to this exact release is also safe to resume.
            prior_major = registry.manifest(major_alias, missing=True)
            allowed = {report["platforms"][arch]["digest"]}
            if prior_major:
                allowed |= {row["digest"] for row in prior_major["document"]["manifests"]
                            if row["platform"]["architecture"] == arch}
            if current and current["digest"] not in allowed:
                raise PublicationError("existing_platform_alias_unverifiable")
            blob = (Path(output) / ("platform-" + arch + ".json")).read_bytes()
            entry = report["platforms"][arch]
            if sha(blob) != entry["digest"]:
                raise PublicationError("saved_platform_digest_mismatch")
            targets[alias] = (blob, entry["descriptor"]["mediaType"], entry["digest"])
    # Platform aliases first; a failed index update can be reconciled on retry.
    order = sorted(targets, key=lambda alias: (alias not in {major_alias + "-" + arch for arch in ARCHES}, alias))
    for alias in order:
        current = registry.manifest(alias, missing=True)
        current_digest = None if current is None else current["digest"]
        if current_digest != snapshots[alias]:
            raise PublicationError("alias_changed_during_promotion")
        blob, media, expected = targets[alias]
        if current_digest != expected:
            registry.put(alias, blob, media)
        report["aliases"][alias] = {"digest": expected, "status": "verified"}
        write_json(Path(output) / "report.json", report)
    report["status"] = "aliases_complete"
    write_json(Path(output) / "report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "publish", "verify", "aliases"))
    parser.add_argument("--plan", required=True)
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--anonymous", action="store_true")
    parser.add_argument("--test-image", help="Disposable localhost registry only")
    args = parser.parse_args()
    report_path = Path(args.output_dir) / "report.json"
    try:
        plan = validate_plan(read_json(args.plan))
        image = selected_image(plan, args.test_image)
        if args.command in {"validate", "publish"}:
            if not args.artifacts_dir:
                raise PublicationError("runtime_artifacts_directory_required")
            callback = validate if args.command == "validate" else publish
            callback(plan, args.artifacts_dir, args.output_dir, image)
        elif args.command == "verify":
            verify(plan, args.output_dir, image, args.anonymous)
        else:
            aliases(plan, args.output_dir, image)
    except (ValueError, KeyError, TypeError, OSError, urllib.error.URLError, subprocess.SubprocessError) as error:
        category = str(error) if isinstance(error, PublicationError) else "publication_validation_failed"
        if report_path.is_file():
            try:
                report = read_json(report_path)
                report.update(status="failed", error_category=category)
                write_json(report_path, report)
            except (ValueError, OSError):
                pass
        raise SystemExit("Image publication failed: " + category) from None


if __name__ == "__main__":
    main()
