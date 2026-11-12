"""Registry promotion regression tests; all disposable state stays under /tmp.

Run: PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/scripts -p test_publish.py
"""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
import urllib.error
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("publish", ROOT / "scripts/ci/publish.py")
publish = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publish)
COMMIT = "a" * 40


def plan(version="0.1.0", kind="stable"):
    return {"schema_version": 1, "repository": "PublicData-stream/pdf2md.mcp",
            "image": publish.IMAGE, "tag": version, "version": version, "kind": kind,
            "revision": COMMIT, "tag_object_sha": "b" * 40,
            "ci": {"run_id": 1, "run_attempt": 1, "workflow_path": ".github/workflows/check.yml",
                   "artifacts": {"amd64": {"id": 11}, "arm64": {"id": 12}}}}


def image_archive(directory, arch, revision=COMMIT, tag=None):
    directory.mkdir(parents=True, exist_ok=True)
    tag = tag or "pdf2md-mcp:ci-" + revision + "-" + arch
    config = publish.encoded({"architecture": arch, "os": "linux", "rootfs": {"type": "layers", "diff_ids": []}})
    name = hashlib.sha256(config).hexdigest() + ".json"
    entries = {name: config,
               "manifest.json": publish.encoded([{"Config": name, "RepoTags": [tag], "Layers": []}])}
    with tarfile.open(directory / "image.tar", "w") as archive:
        for filename, blob in entries.items():
            member = tarfile.TarInfo(filename)
            member.size = len(blob)
            archive.addfile(member, io.BytesIO(blob))
    metadata = {"commit": revision, "arch": arch, "os": "ubuntu-24.04", "image": tag,
                "config_digest": publish.sha(config), "platform": "linux/" + arch,
                "archive_sha256": publish.artifacts.digest(directory / "image.tar")}
    (directory / "manifest.json").write_text(json.dumps(metadata))
    return metadata


class MemoryRegistry:
    def __init__(self):
        self.manifests = {}
        self.configs = {}
        self.writes = []

    def platform(self, tag, config_digest, arch, extra=None):
        doc = {"schemaVersion": 2, "mediaType": publish.MANIFEST,
               "config": {"digest": config_digest}, "layers": []}
        if extra:
            doc.update(extra)
        blob = publish.encoded(doc)
        digest = publish.sha(blob)
        self.configs[config_digest] = (config_digest, "linux/" + arch)
        row = {"blob": blob, "document": doc, "digest": digest}
        self.manifests[tag] = self.manifests[digest] = row
        return row

    def manifest(self, reference, missing=False):
        if reference not in self.manifests:
            if missing:
                return None
            raise publish.PublicationError("registry_request_failed")
        return self.manifests[reference]

    def config(self, manifest):
        if manifest["document"].get("mediaType") not in publish.MANIFEST_TYPES:
            raise publish.PublicationError("platform_manifest_required")
        return self.configs[manifest["document"]["config"]["digest"]]

    def put(self, reference, blob, media):
        document = json.loads(blob)
        digest = publish.sha(blob)
        row = {"blob": blob, "document": document, "digest": digest}
        self.manifests[reference] = self.manifests[digest] = row
        self.writes.append(reference)
        return row


class PublicationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="pdf2md-publication-unit-", dir="/tmp")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.inputs = self.directory / "artifacts"
        self.output = self.directory / "output"
        self.output.mkdir()
        self.plan = plan()
        self.metadata = {arch: image_archive(self.inputs / arch, arch) for arch in publish.ARCHES}
        self.registry = MemoryRegistry()

    def initial(self, selected=None, directory=None):
        selected = selected or self.plan
        directory = directory or self.output
        directory.mkdir(exist_ok=True)
        report = publish.initial_report(selected, publish.IMAGE, self.metadata)
        publish.write_json(directory / "report.json", report)
        return report

    def validate_stub(self, selected, inputs, output, image):
        path = Path(output) / "report.json"
        if path.exists():
            return publish.validated_report(selected, image, output)
        return self.initial(selected, Path(output))

    def docker_stub(self, *arguments, **kwargs):
        if arguments[0] == "push":
            tag = arguments[-1].split(":", 1)[1]
            arch = tag.rsplit("-", 1)[1]
            self.registry.platform(tag, self.metadata[arch]["config_digest"], arch)

    def published(self, selected=None, output=None):
        selected = selected or self.plan
        output = output or self.output
        with patch.object(publish, "validate", side_effect=self.validate_stub), patch.object(publish, "docker", side_effect=self.docker_stub):
            return publish.publish(selected, self.inputs, output, publish.IMAGE, self.registry)

    def verified(self, selected=None, output=None):
        selected = selected or self.plan
        output = output or self.output
        self.published(selected, output)
        return publish.verify(selected, output, publish.IMAGE, True, self.registry, pull=False)

    def test_strict_plan_rejects_bad_tags_kind_and_build_suffix(self):
        for tag, kind in (("v0.1.0", "stable"), ("01.1.0", "stable"), ("0.1.0-beta.0", "beta"),
                          ("0.1.0+meta", "stable"), ("1" * 120 + ".0.0", "stable"), ("0.1.0-build.bbbbbbbb", "build"), ("0.1.0", "beta")):
            with self.subTest(tag=tag, kind=kind), self.assertRaises(publish.PublicationError):
                publish.validate_plan(plan(tag, kind))
        for tag, kind in (("0.1.0", "stable"), ("0.1.0-beta.1", "beta"), ("0.1.0-build.aaaaaaaa", "build")):
            self.assertEqual(publish.validate_plan(plan(tag, kind))["tag"], tag)

    def test_registry_test_override_is_localhost_only(self):
        self.assertEqual(publish.selected_image(self.plan, "127.0.0.1:5000/test/image"), "127.0.0.1:5000/test/image")
        for image in ("other.example/test", "localhost:99999/a", "localhost:5000/a?x", "127.0.0.2:5000/a"):
            with self.subTest(image=image), self.assertRaises(publish.PublicationError):
                publish.selected_image(self.plan, image)

    def test_valid_archives_have_distinct_configuration_identities(self):
        checked = publish.checked_archives(self.plan, self.inputs)
        self.assertEqual(set(checked), set(publish.ARCHES))
        self.assertNotEqual(checked["amd64"]["config_digest"], checked["arm64"]["config_digest"])

    def test_fixture_tag_rejected_before_loading_either_image(self):
        image_archive(self.inputs / "arm64", "arm64", tag="pdf2md-fixture:ci-" + COMMIT + "-arm64")
        with patch.object(publish, "docker") as docker:
            with self.assertRaisesRegex(publish.PublicationError, "tag_mismatch"):
                publish.validate(self.plan, self.inputs, self.output, publish.IMAGE)
            docker.assert_not_called()

    def test_corrupt_second_archive_prevents_all_docker_operations(self):
        with (self.inputs / "arm64/image.tar").open("ab") as stream:
            stream.write(b"corruption")
        with patch.object(publish, "docker") as docker:
            with self.assertRaisesRegex(ValueError, "checksum"):
                publish.validate(self.plan, self.inputs, self.output, publish.IMAGE)
            docker.assert_not_called()

    def test_missing_or_wrong_architecture_artifact_is_rejected(self):
        (self.inputs / "arm64/image.tar").unlink()
        with self.assertRaisesRegex(publish.PublicationError, "missing"):
            publish.checked_archives(self.plan, self.inputs)
        image_archive(self.inputs / "arm64", "amd64", tag="pdf2md-mcp:ci-" + COMMIT + "-arm64")
        with self.assertRaisesRegex(ValueError, "identity"):
            publish.checked_archives(self.plan, self.inputs)

    def test_load_configuration_mismatch_fails_before_publication(self):
        with patch.object(publish, "docker"), patch.object(publish.artifacts, "inspect_image", return_value={"config_digest": "sha256:" + "f" * 64, "platform": "linux/amd64"}):
            with self.assertRaisesRegex(publish.PublicationError, "loaded_runtime"):
                publish.validate(self.plan, self.inputs, self.output, publish.IMAGE)

    def test_publish_creates_two_platform_manifests_and_identical_index_tags(self):
        report = self.published()
        self.assertEqual(report["status"], "published")
        self.assertEqual(report["index_digest"], self.registry.manifest("0.1.0")["digest"])
        self.assertEqual(self.registry.manifest("0.1.0")["blob"], self.registry.manifest("0.1.0-alpine-musl")["blob"])
        index = self.registry.manifest("0.1.0")["document"]
        self.assertEqual([row["platform"]["architecture"] for row in index["manifests"]], ["amd64", "arm64"])
        self.assertEqual(index["annotations"]["org.opencontainers.image.revision"], COMMIT)
        self.assertNotEqual(report["index_digest"], report["platforms"]["amd64"]["config_digest"])

    def test_complete_retry_preserves_all_matching_manifests(self):
        first = self.published()
        self.registry.writes.clear()
        with patch.object(publish, "validate", side_effect=self.validate_stub), patch.object(publish, "docker") as docker:
            second = publish.publish(self.plan, self.inputs, self.output, publish.IMAGE, self.registry)
        docker.assert_not_called()
        self.assertEqual(first, second)
        self.assertEqual(self.registry.writes, [])

    def test_platform_collision_is_rejected_before_any_push(self):
        self.registry.platform("0.1.0-alpine-musl-arm64", "sha256:" + "e" * 64, "arm64")
        with patch.object(publish, "validate", side_effect=self.validate_stub), patch.object(publish, "docker") as docker:
            with self.assertRaisesRegex(publish.PublicationError, "canonical_platform_conflict"):
                publish.publish(self.plan, self.inputs, self.output, publish.IMAGE, self.registry)
        docker.assert_not_called()
        self.assertFalse(self.registry.manifest("0.1.0-alpine-musl-amd64", missing=True))

    def test_partial_platform_publication_can_resume(self):
        self.registry.platform("0.1.0-alpine-musl-amd64", self.metadata["amd64"]["config_digest"], "amd64")
        calls = []
        def docker(*arguments, **kwargs):
            calls.append(arguments)
            self.docker_stub(*arguments, **kwargs)
        with patch.object(publish, "validate", side_effect=self.validate_stub), patch.object(publish, "docker", side_effect=docker):
            publish.publish(self.plan, self.inputs, self.output, publish.IMAGE, self.registry)
        self.assertEqual([args[-1] for args in calls if args[0] == "push"], [publish.IMAGE + ":0.1.0-alpine-musl-arm64"])

    def test_malformed_existing_index_rejects_publication(self):
        self.registry.put("0.1.0", publish.encoded({"schemaVersion": 2, "mediaType": publish.INDEX, "manifests": []}), publish.INDEX)
        with patch.object(publish, "validate", side_effect=self.validate_stub), patch.object(publish, "docker") as docker:
            with self.assertRaisesRegex(publish.PublicationError, "canonical_index_conflict"):
                publish.publish(self.plan, self.inputs, self.output, publish.IMAGE, self.registry)
        docker.assert_not_called()

    def test_canonical_tag_drift_is_detected(self):
        self.published()
        self.registry.platform("0.1.0-alpine-musl-arm64", self.metadata["arm64"]["config_digest"], "arm64", {"annotations": {"changed": "true"}})
        with self.assertRaisesRegex(publish.PublicationError, "canonical_tag_changed"):
            publish.verify(self.plan, self.output, publish.IMAGE, True, self.registry, pull=False)

    def test_anonymous_pull_uses_empty_disposable_credentials(self):
        self.published()
        calls = []
        inspection_references = {}
        def docker(*arguments, env=None):
            self.assertEqual(arguments[0], "--config")
            config = Path(arguments[1])
            self.assertTrue(str(config).startswith("/tmp/"))
            self.assertEqual(json.loads((config / "config.json").read_text()), {"auths": {}})
            self.assertEqual(env["DOCKER_CONFIG"], str(config))
            self.assertEqual(env["DOCKER_HOST"], "unix:///tmp/test.sock")
            self.assertNotIn("DOCKER_CONTEXT", env)
            calls.append(arguments)
            if arguments[2] == "tag":
                inspection_references[arguments[-1]] = arguments[-2]
        def inspected(reference):
            self.assertTrue(reference.startswith("pdf2md-publication-verify:"))
            reference = inspection_references[reference]
            for arch in publish.ARCHES:
                if reference.endswith(self.registry.manifest(publish.platform_tag(self.plan, arch))["digest"]):
                    return {key: self.metadata[arch][key] for key in ("config_digest", "platform")}
            self.fail("unexpected image reference")
        with patch.object(publish, "docker", side_effect=docker), patch.object(publish.artifacts, "inspect_image", side_effect=inspected), patch.object(publish, "docker_endpoint", return_value="unix:///tmp/test.sock"):
            report = publish.verify(self.plan, self.output, publish.IMAGE, True, self.registry)
        self.assertTrue(report["anonymous_verified"])
        self.assertEqual(len(calls), 6)
        self.assertEqual([args[-1] for args in calls if args[2:4] == ("image", "rm")], list(inspection_references))

    def test_anonymous_config_retains_saved_context_daemon(self):
        with patch.dict(os.environ, {"DOCKER_CONTEXT": "rootless", "DOCKER_HOST": "unix:///wrong.sock"}), patch.object(
                publish.subprocess, "run", return_value=SimpleNamespace(stdout="unix:///tmp/rootless.sock\n")) as command:
            self.assertEqual(publish.docker_endpoint(), "unix:///tmp/rootless.sock")
        self.assertEqual(command.call_args[0][0][:3], ["docker", "context", "inspect"])

    def test_aliases_require_prior_anonymous_verification(self):
        self.published()
        with self.assertRaisesRegex(publish.PublicationError, "anonymous_verification_required"):
            publish.aliases(self.plan, self.output, publish.IMAGE, self.registry)

    def test_stable_aliases_advance_and_retry_is_idempotent(self):
        self.verified()
        report = publish.aliases(self.plan, self.output, publish.IMAGE, self.registry)
        expected = {"latest", "alpine-musl", "0-alpine-musl", "0-alpine-musl-amd64", "0-alpine-musl-arm64"}
        self.assertEqual(set(report["aliases"]), expected)
        self.registry.writes.clear()
        publish.aliases(self.plan, self.output, publish.IMAGE, self.registry)
        self.assertEqual(self.registry.writes, [])

    def test_older_release_retry_never_downgrades_aliases(self):
        newer = plan("0.2.0")
        newer_dir = self.directory / "newer"
        self.verified(newer, newer_dir)
        publish.aliases(newer, newer_dir, publish.IMAGE, self.registry)
        digest = self.registry.manifest("latest")["digest"]
        self.verified()
        report = publish.aliases(self.plan, self.output, publish.IMAGE, self.registry)
        self.assertEqual(self.registry.manifest("latest")["digest"], digest)
        self.assertTrue(all(row["status"] == "newer_release_preserved" for row in report["aliases"].values()))

    def test_unverifiable_existing_alias_fails_closed(self):
        self.verified()
        self.registry.put("latest", publish.encoded({"schemaVersion": 2, "mediaType": publish.INDEX, "manifests": []}), publish.INDEX)
        self.registry.writes.clear()
        with self.assertRaisesRegex(publish.PublicationError, "unverifiable"):
            publish.aliases(self.plan, self.output, publish.IMAGE, self.registry)
        self.assertEqual(self.registry.writes, [])

    def test_partial_alias_update_can_resume(self):
        self.verified()
        real_put = self.registry.put
        def fail_index(reference, blob, media):
            if reference == "0-alpine-musl":
                raise publish.PublicationError("registry_request_failed")
            return real_put(reference, blob, media)
        with patch.object(self.registry, "put", side_effect=fail_index):
            with self.assertRaises(publish.PublicationError):
                publish.aliases(self.plan, self.output, publish.IMAGE, self.registry)
        report = publish.aliases(self.plan, self.output, publish.IMAGE, self.registry)
        self.assertEqual(report["status"], "aliases_complete")

    def test_beta_and_build_never_move_aliases(self):
        for version, kind in (("0.1.0-beta.1", "beta"), ("0.1.0-build.aaaaaaaa", "build")):
            with self.subTest(kind=kind):
                directory = self.directory / kind
                selected = plan(version, kind)
                self.verified(selected, directory)
                before = list(self.registry.writes)
                publish.aliases(selected, directory, publish.IMAGE, self.registry)
                self.assertEqual(self.registry.writes, before)

    def test_saved_index_tampering_is_rejected(self):
        self.verified()
        (self.output / "index.json").write_bytes(b"tampered")
        with self.assertRaisesRegex(publish.PublicationError, "saved_index_digest"):
            publish.aliases(self.plan, self.output, publish.IMAGE, self.registry)

    def test_blob_cdn_redirect_strips_registry_authorization(self):
        registry = publish.Registry(publish.IMAGE)
        registry.token = "sensitive-registry-token"
        requests = []
        def read(request):
            requests.append(request)
            if len(requests) == 1:
                raise urllib.error.HTTPError(request.full_url, 307, "redirect", {
                    "Location": "https://pkg-containers.githubusercontent.com/blob?sig=private-url"}, None)
            return b"{}", {}
        with patch.object(registry, "_read", side_effect=read):
            registry.request("blobs", "sha256:" + "a" * 64)
        self.assertTrue(requests[0].has_header("Authorization"))
        self.assertFalse(requests[1].has_header("Authorization"))

    def test_blob_redirect_rejects_untrusted_hosts_and_credentials(self):
        registry = publish.Registry(publish.IMAGE)
        for url in ("http://pkg-containers.githubusercontent.com/blob", "https://evil.example/blob",
                    "https://user:password@pkg-containers.githubusercontent.com/blob",
                    "https://pkg-containers.githubusercontent.com:444/blob",
                    "https://pkg-containers.githubusercontent.com.evil.example/blob"):
            with self.subTest(url=url), patch.object(registry, "_read") as read:
                with self.assertRaisesRegex(publish.PublicationError, "redirect_rejected"):
                    registry._blob_redirect(url)
                read.assert_not_called()

    def test_manifest_and_token_redirects_remain_rejected(self):
        registry = publish.Registry(publish.IMAGE)
        with patch.object(registry, "_read", side_effect=urllib.error.HTTPError(
                "https://ghcr.io/v2/example/manifests/tag", 307, "redirect", {
                    "Location": "https://pkg-containers.githubusercontent.com/blob"}, None)):
            with self.assertRaisesRegex(publish.PublicationError, "registry_redirect_rejected"):
                registry.manifest("tag")

    def test_auth_challenge_cannot_exfiltrate_credentials_to_another_host(self):
        registry = publish.Registry(publish.IMAGE)
        with patch.dict(os.environ, {"GH_TOKEN": "sensitive", "GITHUB_ACTOR": "test"}), patch.object(registry, "_read") as read:
            with self.assertRaisesRegex(publish.PublicationError, "challenge_rejected"):
                registry._authorize('Bearer realm="https://evil.example/token",service="ghcr.io"')
        read.assert_not_called()

    def test_anonymous_registry_token_request_omits_authorization(self):
        registry = publish.Registry(publish.IMAGE, anonymous=True)
        requests = []
        def read(request):
            requests.append(request)
            return b'{"token":"anonymous-token"}', {}
        with patch.dict(os.environ, {"GH_TOKEN": "sensitive", "GITHUB_ACTOR": "test"}), patch.object(registry, "_read", side_effect=read):
            registry._authorize('Bearer realm="https://ghcr.io/token",service="ghcr.io"')
        self.assertFalse(requests[0].has_header("Authorization"))
        self.assertIn("scope=repository%3Apublicdata-stream%2Fpdf2md.mcp%3Apull", requests[0].full_url)


if __name__ == "__main__":
    unittest.main()
