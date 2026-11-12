"""Verify promotion provenance and honest, architecture-specific SBOM coverage."""
import copy
import hashlib
import importlib.util
import json
import os
import subprocess
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

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
        index_blob = b'{"manifests": []}'
        (self.base / "index.json").write_bytes(index_blob)
        self.report = {
            "schema_version": 1, "image": metadata.IMAGE,
            "source": {key: self.plan[key] for key in ("tag", "kind", "revision", "tag_object_sha", "ci")},
            "platforms": {}, "index_digest": "sha256:" + hashlib.sha256(index_blob).hexdigest(),
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

    def test_prepared_sboms_have_fresh_serials_for_attest_cyclonedx_detection(self):
        # actions/attest src/sbom.ts at the workflow's pinned revision requires
        # bomFormat, serialNumber and specVersion to recognize CycloneDX.
        # This compatibility check is not full CycloneDX schema validation.
        serials = set()
        scanner_serial = "urn:uuid:11111111-1111-4111-8111-111111111111"
        for version in ("1.6", "1.7"):
            for has_scanner_serial in (False, True):
                for arch in metadata.ARCHES:
                    path = self.base / ("runtime-" + arch + ".cdx.json")
                    runtime = metadata.read_json(path)
                    runtime["specVersion"] = version
                    if has_scanner_serial:
                        runtime["serialNumber"] = scanner_serial
                    else:
                        runtime.pop("serialNumber", None)
                    metadata.write_json(path, runtime)
                for generation in range(2):
                    metadata.prepare(self.args)
                    for target in (*metadata.ARCHES, "index"):
                        with self.subTest(version=version, scanner_serial=has_scanner_serial,
                                          generation=generation, target=target):
                            sbom = metadata.read_json(self.base / ("sbom-" + target + ".cdx.json"))
                            self.assertEqual(sbom["bomFormat"], "CycloneDX")
                            self.assertEqual(sbom["specVersion"], version)
                            serial = sbom["serialNumber"]
                            identity = uuid.UUID(serial)
                            self.assertEqual(identity.urn, serial)
                            self.assertEqual(identity.version, 4)
                            self.assertEqual(identity.variant, uuid.RFC_4122)
                            self.assertNotEqual(serial, scanner_serial)
                            self.assertNotIn(serial, serials)
                            serials.add(serial)

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

    def test_prepared_promotion_payloads_bind_source_inputs_and_publication(self):
        env = {"GITHUB_WORKFLOW_REF": "owner/repo/.github/workflows/publish.yml@refs/heads/main",
               "GITHUB_WORKFLOW_SHA": "d" * 40, "GITHUB_RUN_ID": "500", "GITHUB_RUN_ATTEMPT": "3"}
        with patch.dict(os.environ, env):
            metadata.prepare(self.args)
        for target in (*metadata.ARCHES, "index"):
            with self.subTest(target=target):
                predicate = metadata.read_json(self.base / ("provenance-" + target + ".json"))
                self.assertEqual(set(predicate), {"operation", "source", "target", "ci", "inputs",
                                                  "platformConfigDigests", "publication"})
                self.assertEqual(predicate["operation"], "promote-tested-images")
                self.assertEqual(predicate["source"], {"tag": self.plan["tag"], "revision": "a" * 40,
                                                       "tagObjectSha": "b" * 40})
                self.assertEqual(predicate["target"], target)
                self.assertEqual(predicate["ci"], self.plan["ci"])
                arches = metadata.ARCHES if target == "index" else (target,)
                expected = [{"uri": "git+" + metadata.SOURCE + ".git@" + "a" * 40,
                             "digest": {"gitCommit": "a" * 40}}]
                expected.extend({"uri": metadata.SOURCE + "/actions/runs/100/artifacts/" +
                                 str(self.plan["ci"]["artifacts"][arch]["id"]),
                                 "digest": {"sha256": self.report["platforms"][arch]["archive_sha256"]}}
                                for arch in arches)
                self.assertEqual(predicate["inputs"], expected)
                self.assertEqual(predicate["platformConfigDigests"],
                                 {arch: self.report["platforms"][arch]["config_digest"] for arch in metadata.ARCHES})
                self.assertEqual(predicate["publication"], {
                    "implementationRevision": "c" * 40, "workflowRef": env["GITHUB_WORKFLOW_REF"],
                    "workflowSha": "d" * 40,
                    "invocationId": metadata.SOURCE + "/actions/runs/500/attempts/3"})

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

    def test_select_binds_every_subject_and_emits_promotion_predicate_type(self):
        metadata.prepare(self.args)
        for target in (*metadata.ARCHES, "index"):
            with self.subTest(target=target):
                output = self.base / ("outputs-" + target)
                args = SimpleNamespace(output_dir=self.base, target=target)
                manifest = self.base / ("index.json" if target == "index" else "platform-" + target + ".json")
                digest = self.report["index_digest"] if target == "index" else self.report["platforms"][target]["digest"]
                with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}):
                    metadata.select(args)
                    values = dict(line.split("=", 1) for line in output.read_text().splitlines())
                    self.assertEqual(values, {"digest": digest, "manifest": str(manifest),
                                              "predicate_type": metadata.SOURCE +
                                              "/blob/main/docs/container-releases.md#image-promotion-v1",
                                              "predicate": str(self.base / ("provenance-" + target + ".json")),
                                              "sbom": str(self.base / ("sbom-" + target + ".cdx.json"))})
                    manifest.write_text("tampered")
                    with self.assertRaisesRegex(ValueError, "subject digest"):
                        metadata.select(args)

    def record_env(self):
        env = {}
        for kind, identity in (("provenance", "123"), ("sbom", "124")):
            bundle = self.base / (kind + "-bundle.json")
            bundle.write_text('{"kind": "' + kind + '"}')
            env[kind.upper() + "_ID"] = identity
            env[kind.upper() + "_URL"] = metadata.SOURCE + "/attestations/" + identity
            env[kind.upper() + "_BUNDLE"] = str(bundle)
        return env

    def verified_records(self):
        metadata.prepare(self.args)
        env = self.record_env()
        with patch.dict(os.environ, env, clear=True):
            for target in (*metadata.ARCHES, "index"):
                metadata.record(SimpleNamespace(output_dir=self.base, target=target))
                for kind in ("provenance", "sbom"):
                    self.assertEqual((self.base / "attestations" / target / (kind + ".json")).read_text(),
                                     Path(env[kind.upper() + "_BUNDLE"]).read_text())

    def test_collection_requires_all_digest_bound_verified_records(self):
        self.verified_records()
        metadata.collect(SimpleNamespace(output_dir=self.base))
        report = metadata.read_json(self.base / "report.json")
        self.assertEqual(set(report["attestations"]), {"amd64", "arm64", "index"})
        for target in (*metadata.ARCHES, "index"):
            row = report["attestations"][target]
            expected = self.report["index_digest"] if target == "index" else self.report["platforms"][target]["digest"]
            self.assertEqual((row["target"], row["digest"], row["verified"]), (target, expected, True))

    def test_collection_rejects_missing_wrong_or_unverified_records_without_changing_report(self):
        self.verified_records()
        path = self.base / "attestations/arm64/record.json"
        original = metadata.read_json(path)
        report = (self.base / "report.json").read_bytes()
        cases = [None, {**original, "target": "amd64"},
                 {**original, "digest": self.report["platforms"]["amd64"]["digest"]},
                 {**original, "verified": False},
                 {**original, "provenance": {"id": "0", "url": metadata.SOURCE + "/attestations/0"}},
                 {**original, "sbom": {"id": "124", "url": "https://github.com/other/repo/attestations/124"}}]
        for row in cases:
            with self.subTest(row=row):
                if row is None:
                    path.unlink()
                else:
                    metadata.write_json(path, row)
                with self.assertRaises(ValueError):
                    metadata.collect(SimpleNamespace(output_dir=self.base))
                self.assertEqual((self.base / "report.json").read_bytes(), report)
                metadata.write_json(path, original)

    def test_record_rejects_invalid_ids_and_references(self):
        metadata.prepare(self.args)
        valid = self.record_env()
        for key, value in (("PROVENANCE_ID", ""), ("PROVENANCE_ID", "0"),
                           ("SBOM_ID", "abc"),
                           ("PROVENANCE_URL", "https://github.com/other/repo/attestations/123"),
                           ("SBOM_URL", metadata.SOURCE + "/attestations/999")):
            with self.subTest(key=key, value=value), patch.dict(os.environ, {**valid, key: value}, clear=True):
                with self.assertRaisesRegex(ValueError, "identity"):
                    metadata.record(SimpleNamespace(output_dir=self.base, target="amd64"))
                self.assertFalse((self.base / "attestations/amd64/record.json").exists())

    def test_workflow_uses_selected_type_and_fails_closed_before_promotion(self):
        workflow = (ROOT / ".github/workflows/publish-images.yml").read_text()
        attest = workflow.split("  attest:\n", 1)[1].split("  qualify:\n", 1)[0]
        qualify = workflow.split("  qualify:\n", 1)[1]
        self.assertIn("target: [amd64, arm64, index]", attest)
        self.assertIn("predicate-type: ${{ steps.subject.outputs.predicate_type }}", attest)
        self.assertIn("predicate-path: ${{ steps.subject.outputs.predicate }}", attest)
        self.assertIn("PROMOTION_PREDICATE_TYPE: ${{ steps.subject.outputs.predicate_type }}", attest)
        guide = (ROOT / "docs/container-releases.md").read_text()
        self.assertIn("## Image promotion v1\n", guide)
        self.assertIn("--predicate-type " + metadata.PROMOTION_PREDICATE_TYPE, guide)
        for bundle, predicate in (("PROVENANCE_BUNDLE", '\"$PROMOTION_PREDICATE_TYPE\"'),
                                  ("SBOM_BUNDLE", "https://cyclonedx.org/bom")):
            command = next(line for line in attest.splitlines() if 'gh attestation verify' in line and bundle in line)
            self.assertIn('--bundle "$' + bundle + '"', command)
            self.assertIn('--repo PublicData-stream/pdf2md.mcp', command)
            self.assertIn('--signer-workflow PublicData-stream/pdf2md.mcp/.github/workflows/publish-images.yml', command)
            self.assertIn('--predicate-type ' + predicate, command)
        self.assertIn("sbom-path: ${{ steps.subject.outputs.sbom }}", attest)
        self.assertIn("needs: [resolve, publish, attest]", qualify)
        gate = qualify.index('run: test "$ATTEST_RESULT" = success')
        self.assertIn("ATTEST_RESULT: ${{ needs.attest.result }}", qualify[:gate])
        for step in ("release_metadata.py collect", "publish.py verify", "publish.py aliases"):
            self.assertGreater(qualify.index(step), gate)
            block = next(block for block in qualify.split("      - ") if step in block)
            self.assertNotIn("\n        if:", block)
        self.assertIn("--anonymous", qualify)
        self.assertIn("- name: Record qualification failure\n        if: failure()", qualify)
        self.assertIn("report['qualification_status'] = 'failed'", qualify)
        self.assertIn("name: ghcr-publication", qualify)
        gate_command = qualify[gate:].splitlines()[0].removeprefix("run: ")
        for result in ("failure", "cancelled", "skipped", "success"):
            exit_code = subprocess.run(["sh", "-c", gate_command],
                                       env={"ATTEST_RESULT": result}, check=False).returncode
            self.assertEqual(exit_code == 0, result == "success")


if __name__ == "__main__":
    unittest.main()
