#!/usr/bin/env python3
"""Test exact-image publication against a disposable local Distribution registry.

Usage: python3 scripts/test-publication.py REGISTRY_IMAGE@sha256:DIGEST
Requires Docker with its data root under /tmp. No production registry is written.
"""
import argparse
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("publication", ROOT / "scripts/ci/publish.py")
publication = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publication)


def run(*args):
    result = subprocess.run(args, capture_output=True, check=True, timeout=300)
    return result.stdout.decode().strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("registry_image", help="Digest-pinned Distribution registry image")
    args = parser.parse_args()
    if not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", args.registry_image):
        raise SystemExit("registry image must be pinned by digest")
    info = json.loads(run("docker", "info", "--format", "{{json .}}"))
    root = Path(info.get("DockerRootDir", "")).resolve()
    if root == Path("/tmp") or Path("/tmp") not in root.parents:
        raise SystemExit("select a disposable Docker daemon with its data root below /tmp")
    name = "pdf2md-publication-" + uuid.uuid4().hex[:12]
    revision = uuid.uuid4().hex + uuid.uuid4().hex[:8]
    tag_name = "pdf2md-mcp:ci-" + revision
    imported = []
    with tempfile.TemporaryDirectory(prefix="pdf2md-publication-", dir="/tmp") as temporary:
        base = Path(temporary)
        storage = base / "registry"
        storage.mkdir()
        output = base / "report"
        inputs = base / "artifacts"
        started = False
        try:
            run("docker", "run", "--detach", "--rm", "--name", name,
                "--publish", "127.0.0.1::5000", "--mount",
                "type=bind,src=" + str(storage) + ",dst=/var/lib/registry", args.registry_image)
            started = True
            port = run("docker", "port", name, "5000/tcp").rsplit(":", 1)[1]
            image = "127.0.0.1:" + port + "/pdf2md-test/runtime"
            deadline = time.monotonic() + 30
            while True:
                try:
                    with urllib.request.urlopen("http://127.0.0.1:" + port + "/v2/", timeout=2):
                        break
                except (OSError, urllib.error.URLError):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("local registry did not become ready") from None
                    time.sleep(0.25)
            for arch in publication.ARCHES:
                rootfs = base / (arch + ".tar")
                with tarfile.open(rootfs, "w") as archive:
                    blob = ("Synthetic redistributable publication fixture: " + arch + "\n").encode()
                    marker = tarfile.TarInfo("fixture")
                    marker.size = len(blob)
                    archive.addfile(marker, io.BytesIO(blob))
                tag = tag_name + "-" + arch
                run("docker", "import", "--platform", "linux/" + arch, str(rootfs), tag)
                imported.append(tag)
                directory = inputs / arch
                directory.mkdir(parents=True)
                archive = directory / "image.tar"
                run("docker", "save", "--output", str(archive), tag)
                metadata = {"commit": revision, "arch": arch, "os": "ubuntu-24.04", "image": tag,
                            "archive_sha256": publication.artifacts.digest(archive)}
                metadata.update(publication.artifacts.archive_image(archive, tag))
                publication.write_json(directory / "manifest.json", metadata)
            plan = {"schema_version": 1, "repository": "PublicData-stream/pdf2md.mcp", "image": publication.IMAGE,
                    "tag": "0.1.0", "version": "0.1.0", "kind": "stable", "revision": revision,
                    "tag_object_sha": "b" * 40, "ci": {"run_id": 1, "run_attempt": 1,
                    "workflow_path": ".github/workflows/check.yml", "artifacts": {
                        "amd64": {"id": 1}, "arm64": {"id": 2}}}}
            publication.validate_plan(plan)
            publication.selected_image(plan, image)
            # Simulate interruption after publishing AMD64; the helper must
            # preserve it while finishing ARM64 and both canonical indexes.
            local_amd = tag_name + "-amd64"
            remote_amd = image + ":0.1.0-alpine-musl-amd64"
            run("docker", "tag", local_amd, remote_amd)
            imported.append(remote_amd)
            run("docker", "push", "--platform", "linux/amd64", remote_amd)
            first = publication.publish(plan, inputs, output, image)
            publication.verify(plan, output, image, anonymous=True)
            publication.aliases(plan, output, image)
            resumed = publication.publish(plan, inputs, output, image)
            assert first["index_digest"] == resumed["index_digest"]
            publication.verify(plan, output, image, anonymous=True)
            publication.aliases(plan, output, image)
            registry = publication.Registry(image, writable=True)
            assert registry.manifest("latest")["digest"] == first["index_digest"]
            # A conflicting canonical tag must fail without replacing it.
            bad = copy.deepcopy(registry.manifest("0.1.0-alpine-musl-amd64")["document"])
            bad["annotations"] = {"fixture": "conflict"}
            conflicting = registry.put("0.1.0-alpine-musl-amd64", publication.encoded(bad), bad["mediaType"])
            try:
                publication.publish(plan, inputs, output, image)
            except publication.PublicationError as error:
                assert str(error) == "canonical_manifest_conflict"
            else:
                raise AssertionError("conflicting canonical tag was accepted")
            assert registry.manifest("0.1.0-alpine-musl-amd64")["digest"] == conflicting["digest"]
            print("PASS local registry roundtrip, two architectures, anonymous pulls, partial retry, aliases and collision rejection")
        finally:
            if started:
                run("docker", "rm", "--force", name)
            # Remove fixture references and their digest aliases; no application
            # image or pre-existing container is touched.
            references = set(imported)
            if 'image' in locals():
                for arch in publication.ARCHES:
                    references.add(image + ":0.1.0-alpine-musl-" + arch)
                report_file = output / "report.json"
                if report_file.exists():
                    report = publication.read_json(report_file)
                    references.update(image + "@" + row["digest"] for row in report["platforms"].values() if row.get("digest"))
            for reference in references:
                subprocess.run(["docker", "image", "rm", "--force", reference],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)


if __name__ == "__main__":
    main()
