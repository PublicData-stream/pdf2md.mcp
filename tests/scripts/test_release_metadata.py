"""Verify promotion provenance and honest, architecture-specific SBOM coverage."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_metadata", ROOT / "scripts/ci/release_metadata.py")
metadata = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(metadata)


class MetadataTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="pdf2md-release-metadata-", dir="/tmp")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.lock_bytes = b'''version = 4
[[package]]
name = "example"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
'''
        self.plan = {
            "schema_version": 1, "repository": metadata.REPOSITORY, "image": metadata.IMAGE,
            "source_url": metadata.SOURCE, "tag": "0.1.0", "kind": "stable", "version": "0.1.0",
            "revision": "a" * 40, "tag_object_sha": "b" * 40, "trusted_revision": "c" * 40,
            "ci": {"run_id": 100, "run_attempt": 2, "workflow_path": ".github/workflows/check.yml",
                   "artifacts": {"amd64": {"id": 101}, "arm64": {"id": 102}}},
            "source_cargo_lock_sha256": hashlib.sha256(self.lock_bytes).hexdigest(),
        }
        self.report = {
            "schema_version": 1, "image": metadata.IMAGE,
            "source": {key: self.plan[key] for key in ("tag", "kind", "revision", "tag_object_sha", "ci")},
            "platforms": {}, "index_digest": "sha256:" + "d" * 64,
        }
        for arch, digit in (("amd64", "e"), ("arm64", "f")):
            blob = json.dumps({"architecture": arch}).encode()
            self.report["platforms"][arch] = {
                "digest": "sha256:" + hashlib.sha256(blob).hexdigest(),
                "config_digest": "sha256:" + digit * 64,
                "platform": "linux/" + arch, "archive_sha256": digit * 64,
            }
            (self.base / ("platform-" + arch + ".json")).write_bytes(blob)
            runtime = {
                "bomFormat": "CycloneDX", "specVersion": "1.6",
                "metadata": {"component": {"type": "container", "name": "runtime", "bom-ref": "root"}},
                "components": [{"type": "library", "name": "musl", "version": "1", "bom-ref": "musl"}],
                "dependencies": [{"ref": "root", "dependsOn": ["musl"]}],
            }
            metadata.write_json(self.base / ("runtime-" + arch + ".cdx.json"), runtime)
        self.lock = self.base / "Cargo.lock"
        self.lock.write_bytes(self.lock_bytes)
        self.plan_path = self.base / "source-plan.json"
        metadata.write_json(self.plan_path, self.plan)
        metadata.write_json(self.base / "report.json", self.report)
        self.args = SimpleNamespace(plan=self.plan_path, lock=self.lock, output_dir=self.base)

    def test_source_inventory_is_distinguished_from_runtime_and_has_integrity(self):
        metadata.prepare(self.args)
        sbom = metadata.read_json(self.base / "sbom-amd64.cdx.json")
        source = sbom["components"][-1]
        self.assertEqual(source["type"], "data")
        self.assertIn("not an exact linked", source["description"])
        self.assertEqual(source["components"][0]["purl"], "pkg:cargo/example@1.2.3")
        self.assertEqual(source["components"][0]["hashes"][0]["content"], "a" * 64)
        self.assertEqual(sbom["metadata"]["component"]["properties"][0]["value"], "linux/amd64")

    def test_index_inventory_keeps_architecture_references_disjoint(self):
        metadata.prepare(self.args)
        index = metadata.read_json(self.base / "sbom-index.cdx.json")
        self.assertEqual(len(index["components"]), 2)
        references = [row["ref"] for row in index["dependencies"]]
        self.assertEqual(references, ["amd64:runtime:root", "arm64:runtime:root"])
        self.assertEqual(index["dependencies"][1]["dependsOn"], ["arm64:runtime:musl"])

    def test_provenance_records_promotion_and_producing_run_without_claiming_rebuild(self):
        predicate = metadata.provenance(self.plan, self.report, "index")
        definition = predicate["buildDefinition"]
        self.assertEqual(definition["externalParameters"]["operation"], "promote-tested-images")
        self.assertEqual(definition["externalParameters"]["ci"]["run_attempt"], 2)
        self.assertEqual(len(definition["resolvedDependencies"]), 3)
        self.assertEqual(definition["internalParameters"]["publicationImplementationRevision"], "c" * 40)

    def test_report_source_mismatch_is_rejected(self):
        changed = copy.deepcopy(self.report)
        changed["source"]["revision"] = "f" * 40
        with self.assertRaisesRegex(ValueError, "does not match"):
            metadata.validate(self.plan, changed)

    def test_missing_architecture_or_config_digest_is_rejected(self):
        for change in (lambda value: value["platforms"].pop("arm64"),
                       lambda value: value["platforms"]["arm64"].update(config_digest="wrong")):
            with self.subTest(change=change):
                changed = copy.deepcopy(self.report)
                change(changed)
                with self.assertRaises(ValueError):
                    metadata.validate(self.plan, changed)

    def test_modified_source_lockfile_is_rejected(self):
        self.lock.write_bytes(self.lock_bytes + b"\n")
        with self.assertRaisesRegex(ValueError, "lockfile does not match"):
            metadata.prepare(self.args)

    def test_empty_runtime_scan_is_rejected(self):
        runtime = {"bomFormat": "CycloneDX", "components": []}
        with self.assertRaisesRegex(ValueError, "runtime scan"):
            metadata.platform_sbom(self.plan, self.report["platforms"]["amd64"], "amd64", runtime, {}, "a" * 64)

    def test_new_scanner_schema_is_preserved_without_downlabelling_components(self):
        runtime = {"bomFormat": "CycloneDX", "specVersion": "1.7", "components": [
            {"type": "library", "name": "musl", "version": "1", "bom-ref": "musl"}]}
        lock = {"package": [{"name": "source", "version": "1"}]}
        result = metadata.platform_sbom(self.plan, self.report["platforms"]["amd64"], "amd64", runtime, lock, "a" * 64)
        self.assertEqual(result["specVersion"], "1.7")
        runtime["specVersion"] = "unknown"
        with self.assertRaisesRegex(ValueError, "runtime scan"):
            metadata.platform_sbom(self.plan, self.report["platforms"]["amd64"], "amd64", runtime, lock, "a" * 64)

    def test_attestation_subject_requires_exact_manifest_bytes(self):
        metadata.prepare(self.args)
        output = self.base / "outputs"
        args = SimpleNamespace(output_dir=self.base, target="amd64")
        with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}):
            metadata.select(args)
            self.assertIn(self.report["platforms"]["amd64"]["digest"], output.read_text())
            (self.base / "platform-amd64.json").write_text("tampered")
            with self.assertRaisesRegex(ValueError, "subject digest"):
                metadata.select(args)

    def verified_records(self):
        metadata.prepare(self.args)
        for target in (*metadata.ARCHES, "index"):
            digest = self.report["index_digest"] if target == "index" else self.report["platforms"][target]["digest"]
            destination = self.base / "attestations" / target
            destination.mkdir(parents=True)
            row = {"target": target, "digest": digest, "verified": True}
            for kind, identity in (("provenance", "123"), ("sbom", "124")):
                row[kind] = {"id": identity, "url": metadata.SOURCE + "/attestations/" + identity}
            metadata.write_json(destination / "record.json", row)

    def test_collection_requires_all_digest_bound_verified_records(self):
        self.verified_records()
        metadata.collect(SimpleNamespace(output_dir=self.base))
        report = metadata.read_json(self.base / "report.json")
        self.assertEqual(set(report["attestations"]), {"amd64", "arm64", "index"})
        path = self.base / "attestations/arm64/record.json"
        row = metadata.read_json(path)
        row["digest"] = self.report["platforms"]["amd64"]["digest"]
        metadata.write_json(path, row)
        with self.assertRaisesRegex(ValueError, "does not match"):
            metadata.collect(SimpleNamespace(output_dir=self.base))

    def test_partial_attestation_matrix_cannot_qualify_publication(self):
        self.verified_records()
        (self.base / "attestations/index/record.json").unlink()
        with self.assertRaises(ValueError):
            metadata.collect(SimpleNamespace(output_dir=self.base))

    def test_record_rejects_attestation_reference_from_another_repository(self):
        metadata.prepare(self.args)
        bundle = self.base / "bundle.json"
        bundle.write_text('{}')
        env = {"PROVENANCE_ID": "123", "PROVENANCE_URL": "https://github.com/other/repo/attestations/123",
               "PROVENANCE_BUNDLE": str(bundle)}
        with patch.dict(os.environ, env), self.assertRaisesRegex(ValueError, "identity"):
            metadata.record(SimpleNamespace(output_dir=self.base, target="amd64"))


if __name__ == "__main__":
    unittest.main()
