"""Regression tests for CI artifact identity and aggregate gating.

Run: PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/scripts -p test_ci.py
"""
import argparse
import contextlib
import importlib.util
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path
import tempfile
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts/ci" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


artifacts = load("artifacts")
check = load("check")
COMMIT = "a" * 40


def executable(path, machine=62):
    path.parent.mkdir(parents=True, exist_ok=True)
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    header[18:20] = machine.to_bytes(2, "little")
    path.write_bytes(header)
    path.chmod(0o755)


def image_export(path, image="pdf2md:ci", style="classic", config=None):
    config = config or {"architecture": "amd64", "os": "linux", "config": {"Env": ["EXAMPLE=1"]}}
    config_blob = json.dumps(config).encode()
    config_hash = hashlib.sha256(config_blob).hexdigest()
    config_name = config_hash + ".json" if style == "classic" else "blobs/sha256/" + config_hash
    files = {config_name: config_blob}
    if style == "oci":
        manifest = {"schemaVersion": 2, "config": {"digest": "sha256:" + config_hash}, "layers": []}
        blob = json.dumps(manifest).encode()
        manifest_hash = hashlib.sha256(blob).hexdigest()
        files["blobs/sha256/" + manifest_hash] = blob
        files["index.json"] = json.dumps({"schemaVersion": 2, "manifests": [{"digest": "sha256:" + manifest_hash}]}).encode()
    else:
        files["manifest.json"] = json.dumps([{"Config": config_name, "RepoTags": [image], "Layers": []}]).encode()
        if style == "containerd":
            files["index.json"] = b'{"schemaVersion":2,"manifests":[]}'
    with tarfile.open(path, "w") as archive:
        for name, blob in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(blob)
            archive.addfile(member, io.BytesIO(blob))
    return {"config_digest": "sha256:" + config_hash,
            "platform": config["os"] + "/" + config["architecture"]}


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="pdf2md-ci-test-", dir="/tmp")
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.target = self.base / "target"
        for name in ("pdf2md-mcp", "pdf2md-convert-worker", "pdf2md-obscura-worker",
                     "deps/browser-test", "deps/provider-test"):
            executable(self.target / "debug" / name)
        rows = []
        for name, kind, file in (("pdf2md_mcp", "lib", "browser-test"),
                                 ("live_casdoor", "test", "provider-test")):
            rows.append({"reason": "compiler-artifact", "target": {"name": name, "kind": [kind]},
                         "executable": str(self.target / "debug/deps" / file)})
        self.cargo = self.base / "cargo.json"
        self.cargo.write_text("\n".join(json.dumps(row) for row in rows))
        self.bundle = self.base / "bundle"
        self.pack = argparse.Namespace(commit=COMMIT, arch="amd64", target_dir=self.target,
                                       cargo_json=self.cargo, output=self.bundle)
        self.restore = argparse.Namespace(commit=COMMIT, arch="amd64", target_dir=self.base / "restored",
                                          input=self.bundle)

    def test_native_bundle_restores_only_bound_executables_and_exports_paths(self):
        artifacts.pack_native(self.pack)
        environment = self.base / "env"
        with patch.dict(os.environ, {"GITHUB_ENV": str(environment)}), patch.object(artifacts.platform, "machine", return_value="x86_64"):
            artifacts.restore_native(self.restore)
        self.assertTrue(os.access(self.base / "restored/debug/deps/browser-test", os.X_OK))
        self.assertIn("PDF2MD_BROWSER_TEST_EXECUTABLE=", environment.read_text())
        self.assertIn("PDF2MD_LIVE_CASDOOR_TEST_EXECUTABLE=", environment.read_text())

    def test_missing_test_executable_rejects_bundle(self):
        self.cargo.write_text("")
        with self.assertRaisesRegex(ValueError, "missing"):
            artifacts.pack_native(self.pack)

    def test_wrong_executable_architecture_rejects_bundle(self):
        executable(self.target / "debug/pdf2md-mcp", 183)
        with self.assertRaisesRegex(ValueError, "architecture"):
            artifacts.pack_native(self.pack)

    def test_non_executable_binary_rejects_bundle(self):
        (self.target / "debug/pdf2md-mcp").chmod(0o644)
        with self.assertRaisesRegex(ValueError, "not executable"):
            artifacts.pack_native(self.pack)

    def test_commit_and_archive_tampering_fail_before_restore(self):
        artifacts.pack_native(self.pack)
        self.restore.commit = "b" * 40
        with self.assertRaisesRegex(ValueError, "identity"):
            artifacts.restore_native(self.restore)
        self.restore.commit = COMMIT
        with (self.bundle / "native.tar.gz").open("ab") as stream:
            stream.write(b"tampered")
        with self.assertRaisesRegex(ValueError, "checksum"):
            artifacts.restore_native(self.restore)
        self.assertFalse((self.base / "restored").exists())

    def test_existing_parent_symlink_cannot_redirect_extraction(self):
        artifacts.pack_native(self.pack)
        outside = self.base / "outside"
        outside.mkdir()
        target = self.base / "restored/debug"
        target.mkdir(parents=True)
        (target / "deps").symlink_to(outside, target_is_directory=True)
        with patch.object(artifacts.platform, "machine", return_value="x86_64"):
            with self.assertRaisesRegex(ValueError, "symlink"):
                artifacts.restore_native(self.restore)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse((target / "pdf2md-mcp").exists())

    def test_runner_architecture_mismatch_is_rejected(self):
        artifacts.pack_native(self.pack)
        with patch.object(artifacts.platform, "machine", return_value="aarch64"):
            with self.assertRaisesRegex(ValueError, "runner"):
                artifacts.restore_native(self.restore)

    def test_image_load_compares_configuration_identity(self):
        image = self.base / "source.tar"
        observed = image_export(image)
        args = argparse.Namespace(commit=COMMIT, arch="amd64", image="pdf2md:ci", archive=image,
                                  output=self.bundle)
        with patch.object(artifacts, "inspect_image", return_value=observed):
            artifacts.pack_image(args)
        args = argparse.Namespace(commit=COMMIT, arch="amd64", input=self.bundle, env_name="CI_IMAGE")
        wrong = dict(observed, config_digest="sha256:" + "2" * 64)
        with patch.object(artifacts.subprocess, "run"), patch.object(artifacts, "inspect_image", return_value=wrong):
            with self.assertRaisesRegex(ValueError, "identity"):
                artifacts.load_image(args)

    def test_fixture_image_does_not_replace_runtime_digest(self):
        image = self.base / "source.tar"
        observed = image_export(image, image="pdf2md:fixture")
        with patch.object(artifacts, "inspect_image", return_value=observed):
            artifacts.pack_image(argparse.Namespace(commit=COMMIT, arch="amd64", image="pdf2md:fixture",
                                                   archive=image, output=self.bundle))
        output = self.base / "env"
        args = argparse.Namespace(commit=COMMIT, arch="amd64", input=self.bundle, env_name="PDF2MD_FIXTURE_IMAGE")
        with patch.object(artifacts.subprocess, "run"), patch.object(artifacts, "inspect_image", return_value=observed), patch.dict(os.environ, {"GITHUB_ENV": str(output)}):
            artifacts.load_image(args)
        self.assertEqual(output.read_text(), "PDF2MD_FIXTURE_IMAGE=pdf2md:fixture\n")


    def test_classic_and_containerd_exports_use_config_blob_not_inspect_id(self):
        for style in ("classic", "containerd"):
            with self.subTest(style=style):
                image = self.base / (style + ".tar")
                expected = image_export(image, style=style)
                inspect_id = expected["config_digest"] if style == "classic" else "sha256:" + "9" * 64

                def docker(args, **kwargs):
                    if args[1:3] == ["image", "inspect"]:
                        return SimpleNamespace(stdout=json.dumps([{"Id": inspect_id, "Os": "linux", "Architecture": "amd64"}]))
                    if args[1:3] == ["image", "save"]:
                        Path(args[4]).write_bytes(image.read_bytes())
                        return SimpleNamespace(returncode=0)
                    self.fail("unexpected Docker command")

                with patch.object(artifacts.subprocess, "run", side_effect=docker):
                    self.assertEqual(artifacts.inspect_image("pdf2md:ci", image), expected)
                    self.assertEqual(artifacts.inspect_image("pdf2md:ci"), expected)

    def test_oci_only_archive_resolves_config_descriptor(self):
        image = self.base / "oci.tar"
        expected = image_export(image, style="oci")
        self.assertEqual(artifacts.archive_image(image, "pdf2md:ci"), expected)

    def test_archive_wrong_tag_and_platform_are_rejected(self):
        image = self.base / "image.tar"
        image_export(image, image="pdf2md:other")
        with self.assertRaisesRegex(ValueError, "expected tag"):
            artifacts.archive_image(image, "pdf2md:ci")
        image_export(image, config={"architecture": "arm64", "os": "linux"})
        row = SimpleNamespace(stdout=json.dumps([{"Id": "sha256:" + "9" * 64, "Os": "linux", "Architecture": "amd64"}]))
        with patch.object(artifacts.subprocess, "run", return_value=row):
            with self.assertRaisesRegex(ValueError, "platform disagree"):
                artifacts.inspect_image("pdf2md:ci", image)


class GateTests(unittest.TestCase):
    def needs(self, extended=False):
        return {name: {"result": "success" if name in check.REQUIRED or extended else "skipped"}
                for name in check.REQUIRED | check.EXTENDED}

    def run_summary(self, needs, extended=False):
        with contextlib.redirect_stdout(io.StringIO()), patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": ""}):
            check.summary(needs, extended)

    def test_standard_and_extended_success(self):
        self.run_summary(self.needs())
        self.run_summary(self.needs(True), True)

    def test_failed_cancelled_skipped_or_missing_required_job_fails(self):
        for result in ("failure", "cancelled", "skipped", "missing"):
            with self.subTest(result=result):
                needs = self.needs()
                if result == "missing":
                    del needs["images"]
                else:
                    needs["images"]["result"] = result
                with self.assertRaises(ValueError):
                    self.run_summary(needs)

    def test_extended_jobs_cannot_silently_skip_on_schedule(self):
        with self.assertRaises(ValueError):
            self.run_summary(self.needs(), True)

    def test_actual_inline_gate_matches_helper_for_required_statuses(self):
        workflow = (ROOT / ".github/workflows/check.yml").read_text()
        found = re.search(r"python3 - <<'PYTHON'\n(.*?)^          PYTHON$", workflow, re.S | re.M)
        self.assertIsNotNone(found, "workflow inline summary code was not found")
        code = textwrap.dedent(found[1])
        cases = [(self.needs(), False), (self.needs(True), True)]
        for result in ("failure", "cancelled", "skipped", "missing"):
            needs = self.needs()
            if result == "missing":
                del needs["core"]
            else:
                needs["core"]["result"] = result
            cases.append((needs, False))
        cases.append((self.needs(), True))
        for result in ("success", "failure", "cancelled", "missing"):
            needs = self.needs()
            if result == "missing":
                del needs["extended-browser"]
            else:
                needs["extended-browser"]["result"] = result
            cases.append((needs, False))
        for needs, extended in cases:
            with self.subTest(needs=needs, extended=extended):
                try:
                    self.run_summary(needs, extended)
                    expected = 0
                except ValueError:
                    expected = 1
                with tempfile.TemporaryDirectory(prefix="pdf2md-ci-gate-", dir="/tmp") as temp:
                    env = os.environ.copy()
                    env.update(NEEDS_JSON=json.dumps(needs), EXTENDED=str(extended).lower(),
                               GITHUB_STEP_SUMMARY=str(Path(temp) / "summary"))
                    result = subprocess.run([sys.executable, "-c", code], env=env,
                                            capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_source_check_covers_external_composite_actions(self):
        with tempfile.TemporaryDirectory(prefix="pdf2md-ci-source-", dir="/tmp") as temp:
            root = Path(temp)
            (root / ".github/workflows").mkdir(parents=True)
            (root / ".github/actions/setup").mkdir(parents=True)
            (root / "scripts/ci").mkdir(parents=True)
            (root / ".github/workflows/check.yml").write_text("steps:\n  - uses: ./.github/actions/setup\n")
            (root / "Dockerfile").write_text("FROM debian:bookworm@sha256:" + "1" * 64 + "\n")
            catalog = "services:\n" + "".join("  " + name + ":\n    image: test:1@sha256:" + "1" * 64 + "\n" for name in check.IMAGE_ENV)
            (root / "scripts/ci/compose.yml").write_text(catalog)
            action = root / ".github/actions/setup/action.yml"
            action.write_text("runs:\n  steps:\n    - uses: docker/setup-docker-action@v5\n")
            with self.assertRaisesRegex(ValueError, "full commit SHA"):
                check.source(root)
            action.write_text("runs:\n  steps:\n    - uses: docker/setup-docker-action@" + "1" * 40 + "\n")
            with contextlib.redirect_stdout(io.StringIO()):
                check.source(root)

    def test_source_check_rejects_mutable_actions_and_images(self):
        with tempfile.TemporaryDirectory(prefix="pdf2md-ci-source-", dir="/tmp") as temp:
            root = Path(temp)
            (root / ".github/workflows").mkdir(parents=True)
            (root / "scripts/ci").mkdir(parents=True)
            workflow = root / ".github/workflows/check.yml"
            workflow.write_text("steps:\n  - uses: actions/checkout@v4\n")
            (root / "Dockerfile").write_text("FROM debian:bookworm\n")
            (root / "scripts/ci/compose.yml").write_text("services:\n  provider:\n    image: casbin/casdoor:latest\n")
            with self.assertRaisesRegex(ValueError, "full commit SHA"):
                check.source(root)
            workflow.write_text("steps:\n  - uses: actions/checkout@" + "1" * 40 + "\n")
            with self.assertRaisesRegex(ValueError, "base image"):
                check.source(root)


class LaneTests(unittest.TestCase):
    def run_lane(self, cargo_exit=0, cleanup_exit=0):
        with tempfile.TemporaryDirectory(prefix="pdf2md-ci-lane-test-", dir="/tmp") as temp:
            base = Path(temp)
            docker = base / "docker"
            docker.write_text("""#!/usr/bin/env python3
import json, os, sys
if sys.argv[1] == "info":
    print(json.dumps({"SecurityOptions": ["name=rootless"], "DockerRootDir": "/tmp/docker-test"}))
elif sys.argv[1] == "port":
    print("127.0.0.1:15432")
elif sys.argv[1] == "rm":
    sys.exit(int(os.environ["FAKE_CLEANUP_EXIT"]))
""")
            docker.chmod(0o755)
            cargo = base / "cargo"
            cargo.write_text("#!/bin/sh\necho 'test result: ok. 1 passed; 0 failed;'\nexit \"$FAKE_CARGO_EXIT\"\n")
            cargo.chmod(0o755)
            env = os.environ.copy()
            env.update(PATH=str(base) + os.pathsep + env["PATH"], PDF2MD_POSTGRES_IMAGE="postgres:test",
                       FAKE_CARGO_EXIT=str(cargo_exit), FAKE_CLEANUP_EXIT=str(cleanup_exit), GITHUB_ACTIONS="false",
                       PDF2MD_CI_DIAGNOSTICS_DIR=str(base / "diagnostics"))
            result = subprocess.run(["bash", str(ROOT / "scripts/ci/run.sh"), "core-postgres"],
                                  env=env, capture_output=True, text=True, timeout=15)
            result.diagnostics = json.loads((base / "diagnostics/core-postgres.json").read_text())
            return result

    def test_lane_preserves_test_failure(self):
        result = self.run_lane(cargo_exit=7)
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(result.diagnostics, {"lane": "core-postgres", "status": "failure", "exit_code": 7})
        self.assertNotIn("PASS CI lane", result.stdout)

    def test_lane_rejects_unconfirmed_cleanup_after_success(self):
        result = self.run_lane(cleanup_exit=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cleanup failed or is unconfirmed", result.stderr)
        self.assertNotIn("PASS CI lane", result.stdout)

    def test_cleanup_does_not_replace_original_test_failure(self):
        result = self.run_lane(cargo_exit=7, cleanup_exit=1)
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(result.diagnostics, {"lane": "core-postgres", "status": "failure", "exit_code": 7})
        self.assertIn("cleanup failed or is unconfirmed", result.stderr)

    def test_lane_returns_success_only_after_cleanup(self):
        result = self.run_lane()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.diagnostics, {"lane": "core-postgres", "status": "success", "exit_code": 0})


if __name__ == "__main__":
    unittest.main()
