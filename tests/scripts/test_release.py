"""Release source and exact-CI gate regression tests.

Run: PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/scripts -p test_release.py
"""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_gate", ROOT / "scripts/ci/release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
COMMIT = "a" * 40
ANNOTATION = "b" * 40
TRUSTED = "c" * 40
TAG = "0.1.0-build.aaaaaaaa"


def run_row(run_id=10):
    return {"id": run_id, "path": release.WORKFLOW, "event": "push", "head_branch": "main",
            "head_sha": COMMIT, "repository": {"full_name": release.REPOSITORY},
            "head_repository": {"full_name": release.REPOSITORY}, "status": "completed",
            "conclusion": "success", "run_attempt": 2, "workflow_id": 99}


def summary():
    return {"name": "CI summary", "head_sha": COMMIT, "status": "completed", "conclusion": "success"}


def producer(arch):
    return {"name": f"Build container images ({arch})", "head_sha": COMMIT,
            "status": "completed", "conclusion": "success", "started_at": "2026-01-01T00:00:00Z",
            "completed_at": "2026-01-01T00:10:00Z", "run_attempt": 1}


def artifact(arch):
    return {"id": 101 if arch == "amd64" else 102, "name": "image-" + arch, "expired": False,
            "created_at": "2026-01-01T00:05:00Z",
            "workflow_run": {"id": 10, "head_sha": COMMIT, "head_branch": "main"}}


class CiTests(unittest.TestCase):
    def setUp(self):
        self.runs = [run_row()]
        self.current = run_row()
        self.summaries = [summary()]
        self.producers = [producer(arch) for arch in ("amd64", "arm64")]
        self.artifacts = [artifact(arch) for arch in ("amd64", "arm64")]
        self.get_calls = 0
        self.final = None
        self.calls = []

    def api(self, endpoint, optional=False):
        self.calls.append(endpoint)
        path = urlsplit(endpoint).path
        if path.endswith("/check.yml/runs"):
            return {"workflow_runs": self.runs}
        if path.endswith("/attempts/2/jobs"):
            return {"jobs": self.summaries}
        if path.endswith("/jobs"):
            return {"jobs": self.producers}
        if path.endswith("/artifacts"):
            return {"artifacts": self.artifacts}
        if path.endswith("/runs/10") or path.endswith("/runs/11"):
            self.get_calls += 1
            return self.final if self.final is not None and self.get_calls > 1 else self.current
        self.fail("unexpected API request: " + endpoint)

    def identity(self):
        with patch.object(release, "api", side_effect=self.api):
            return release.ci_identity(COMMIT)

    def test_binds_two_artifacts_and_accepts_successful_earlier_producers_on_partial_rerun(self):
        actual = self.identity()
        self.assertEqual(actual["run_attempt"], 2)
        self.assertEqual(actual["artifacts"], {"amd64": {"id": 101, "name": "image-amd64"},
                                               "arm64": {"id": 102, "name": "image-arm64"}})
        self.assertIn("filter=all", " ".join(self.calls))

    def test_accepts_carried_forward_jobs_with_new_ids_and_attempts(self):
        self.producers = []
        for arch, runner_id in (("amd64", 1001), ("arm64", 1002)):
            original = {**producer(arch), "id": runner_id, "runner_id": runner_id,
                        "runner_group_id": 0}
            carried = {**original, "id": runner_id + 100, "run_attempt": 2,
                       "runner_group_id": None}
            self.producers.extend((original, carried))
        actual = self.identity()
        self.assertEqual(actual["artifacts"], {"amd64": {"id": 101, "name": "image-amd64"},
                                               "arm64": {"id": 102, "name": "image-arm64"}})

    def test_rejects_distinct_matching_producer_executions(self):
        original = {**producer("amd64"), "id": 1, "runner_id": 1001}
        for field, value in (("runner_id", 1002), ("started_at", "2026-01-01T00:01:00Z"),
                             ("completed_at", "2026-01-01T00:09:00Z")):
            with self.subTest(field=field):
                other = {**original, "id": 2, "run_attempt": 2, field: value}
                self.producers = [original, other, producer("arm64")]
                with self.assertRaisesRegex(ValueError, "ambiguous image producer executions"):
                    self.identity()

    def test_rejects_duplicate_producers_without_verified_runner_identity(self):
        original = {**producer("amd64"), "runner_id": 1001}
        for runner_id in (None, 0, -1, True, "1001", [], {}):
            with self.subTest(runner_id=runner_id):
                self.producers = [original, {**original, "runner_id": runner_id}, producer("arm64")]
                with self.assertRaisesRegex(ValueError, "ambiguous image producer executions"):
                    self.identity()
        missing = producer("amd64")
        self.producers = [missing, missing.copy(), producer("arm64")]
        with self.assertRaisesRegex(ValueError, "ambiguous image producer executions"):
            self.identity()

    def test_preserves_single_producer_without_runner_metadata(self):
        self.assertEqual(self.identity()["run_id"], 10)

    def test_excludes_jobs_without_successful_exact_source_execution_window(self):
        for field, value in (("head_sha", "d" * 40), ("status", "in_progress"),
                             ("conclusion", "failure"), ("started_at", None),
                             ("completed_at", None), ("started_at", "2026-01-01T00:06:00Z"),
                             ("completed_at", "2026-01-01T00:04:00Z")):
            with self.subTest(field=field):
                self.producers = [{**producer("amd64"), field: value}, producer("arm64")]
                with self.assertRaisesRegex(ValueError, "no successful exact-source image job"):
                    self.identity()

    def test_reports_expiry_and_origin_failures_separately(self):
        for field, value, message in (("expired", True, "expired"),
                                     ("expired", None, "expiry is unverifiable"),
                                     ("id", True, "invalid exact-source origin"),
                                     ("workflow_run", None, "invalid exact-source origin"),
                                     ("workflow_run", {"id": 9}, "invalid exact-source origin")):
            with self.subTest(field=field, value=value):
                self.artifacts = [{**artifact("amd64"), field: value}, artifact("arm64")]
                with self.assertRaisesRegex(ValueError, message):
                    self.identity()

    def test_newest_failed_run_cannot_fall_back_to_older_success(self):
        self.runs.append(run_row(11))
        self.current = run_row(11)
        self.current["conclusion"] = "failure"
        with self.assertRaisesRegex(ValueError, "newest"):
            self.identity()

    def test_rejects_pending_cancelled_and_untrusted_run_identities(self):
        for field, value in (("status", "in_progress"), ("conclusion", "cancelled"),
                             ("path", "other.yml"), ("head_sha", "d" * 40),
                             ("run_attempt", 0), ("workflow_id", False)):
            with self.subTest(field=field):
                self.current = run_row()
                self.current[field] = value
                with self.assertRaises(ValueError):
                    self.identity()

    def test_ignores_pull_requests_forks_and_other_branches(self):
        for field, value in (("event", "pull_request"), ("head_branch", "feature"),
                             ("head_repository", {"full_name": "fork/repo"})):
            with self.subTest(field=field):
                self.runs = [run_row()]
                self.runs[0][field] = value
                with self.assertRaisesRegex(ValueError, "no canonical"):
                    self.identity()

    def test_requires_exactly_one_successful_summary_for_source(self):
        for summaries in ([], [summary(), summary()], [{**summary(), "conclusion": "failure"}],
                          [{**summary(), "head_sha": "d" * 40}]):
            with self.subTest(summaries=summaries):
                self.summaries = summaries
                with self.assertRaisesRegex(ValueError, "CI summary"):
                    self.identity()

    def test_rejects_missing_ambiguous_expired_and_foreign_artifacts(self):
        cases = [[], self.artifacts + [artifact("amd64")]]
        for field, value in (("expired", True), ("id", True), ("created_at", "2026-01-02T00:00:00Z"),
                             ("workflow_run", {"id": 9, "head_sha": COMMIT, "head_branch": "main"})):
            rows = [artifact(arch) for arch in ("amd64", "arm64")]
            rows[0][field] = value
            cases.append(rows)
        for rows in cases:
            with self.subTest(rows=rows):
                self.artifacts = rows
                with self.assertRaises(ValueError):
                    self.identity()

    def test_rejects_unsuccessful_or_ambiguous_producer_jobs(self):
        for producers in ([], [{**producer("amd64"), "conclusion": "failure"}, producer("arm64")],
                          [producer("amd64"), producer("amd64"), producer("arm64")]):
            with self.subTest(producers=producers):
                self.producers = producers
                with self.assertRaisesRegex(ValueError, "no successful exact-source image job|ambiguous image producer executions"):
                    self.identity()

    def test_rejects_ci_attempt_race(self):
        self.final = {**run_row(), "run_attempt": 3}
        with self.assertRaisesRegex(ValueError, "changed"):
            self.identity()


class ContractTests(unittest.TestCase):
    def test_strict_supported_tags(self):
        for tag, kind in (("0.1.0", "stable"), ("12.34.56-beta.1", "beta"), (TAG, "build")):
            self.assertEqual(release.parse_tag(tag)["kind"], kind)
        for tag in ("v0.1.0", "01.1.0", "1.01.0", "1.0.01", "1.0.0-beta.0", "1.0.0-beta.01",
                    "1.0.0-alpha.1", "1.0.0+metadata", "1.0.0-build.AAAAAAAA", "1.0.0-build.aaaaaaa",
                    "1.0.0-build.aaaaaaaaa", "1.0.0\n", "$(id)", None, "x" * 129):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release.parse_tag(tag)

    def test_api_http_status_and_json_validation(self):
        with patch.object(release, "run", return_value=(0, b'HTTP/2.0 200 OK\r\nContent-Type: application/json\r\n\r\n{"id":1}', b"")):
            self.assertEqual(release.api("endpoint"), {"id": 1})
        with patch.object(release, "run", return_value=(1, b'HTTP/2.0 404 Not Found\n\n{}', b"")):
            self.assertIsNone(release.api("endpoint", optional=True))
            with self.assertRaises(ValueError):
                release.api("endpoint")
        with patch.object(release, "run", return_value=(1, b'HTTP/2.0 403 Forbidden\n\n{}', b"")):
            with self.assertRaises(ValueError):
                release.api("endpoint", optional=True)
        with patch.object(release, "run", return_value=(0, b'not an HTTP response', b"")):
            with self.assertRaises(ValueError):
                release.api("endpoint")

    def test_pagination_includes_every_page_and_enforces_bound(self):
        with patch.object(release, "api", side_effect=[{"items": list(range(100))}, {"items": [100]}]) as api:
            self.assertEqual(release.pages("endpoint?filter=all", "items"), list(range(101)))
            self.assertIn("&per_page=100&page=2", api.call_args.args[0])
        with patch.object(release, "MAX_PAGES", 1), patch.object(release, "api", return_value={"items": list(range(100))}):
            with self.assertRaisesRegex(ValueError, "pagination bound"):
                release.pages("endpoint", "items")

    def test_manual_requires_main_and_canonical_repository(self):
        environment = {"GITHUB_REPOSITORY": release.REPOSITORY, "GITHUB_REF": "refs/heads/main"}
        event = {"repository": {"full_name": release.REPOSITORY}}
        release.validate_event(TAG, "build", "workflow_dispatch", event, environment)
        for update in ({"GITHUB_REF": "refs/tags/" + TAG}, {"GITHUB_REPOSITORY": "other/repo"}):
            with self.assertRaises(ValueError):
                release.validate_event(TAG, "build", "workflow_dispatch", event, {**environment, **update})

    def test_push_accepts_only_new_build_tag_creation(self):
        environment = {"GITHUB_REPOSITORY": release.REPOSITORY, "GITHUB_REF": "refs/tags/" + TAG}
        event = {"repository": {"full_name": release.REPOSITORY}, "ref": environment["GITHUB_REF"],
                 "deleted": False, "created": True, "forced": False}
        release.validate_event(TAG, "build", "push", event, environment)
        for update in ({"deleted": True}, {"created": False}, {"forced": True}, {"ref": "refs/heads/main"}):
            with self.assertRaises(ValueError):
                release.validate_event(TAG, "build", "push", {**event, **update}, environment)
        with self.assertRaises(ValueError):
            release.validate_event("0.1.0", "stable", "push", event, environment)

    def test_release_event_requires_matching_published_class(self):
        environment = {"GITHUB_REPOSITORY": release.REPOSITORY, "GITHUB_REF": "refs/tags/0.1.0-beta.1"}
        metadata = {"id": 1, "tag_name": "0.1.0-beta.1", "draft": False,
                    "prerelease": True, "published_at": "2026-01-01T00:00:00Z"}
        event = {"repository": {"full_name": release.REPOSITORY}, "action": "published", "release": metadata}
        release.validate_event(metadata["tag_name"], "beta", "release", event, environment)
        for field, value in (("prerelease", False), ("draft", True), ("published_at", None), ("id", True)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                release.validate_event(metadata["tag_name"], "beta", "release",
                                       {**event, "release": {**metadata, field: value}}, environment)

    def test_release_state_rechecked_even_for_manual_dispatch(self):
        with patch.object(release, "api", return_value={"id": 1}):
            with self.assertRaisesRegex(ValueError, "must not have"):
                release.release_state(TAG, "build", "workflow_dispatch", {})
        for document in (None, {"id": 1, "tag_name": "0.1.0", "draft": False,
                                "prerelease": True, "published_at": "2026-01-01T00:00:00Z"}):
            with patch.object(release, "api", return_value=document), self.assertRaises(ValueError):
                release.release_state("0.1.0", "stable", "workflow_dispatch", {})


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.info = release.parse_tag(TAG)
        self.remote = {"object": {"type": "tag", "sha": ANNOTATION}}
        self.annotation = {"sha": ANNOTATION, "tag": TAG, "object": {"type": "commit", "sha": COMMIT}}
        self.version = "0.1.0"
        self.calls = []
        self.fail_ancestry = False
        self.moved = False

    def git(self, *args):
        self.calls.append(args)
        if args[0] == "fetch":
            return ""
        if args[0] == "merge-base":
            if self.fail_ancestry:
                raise ValueError("not ancestor")
            return ""
        if args[0] == "rev-parse":
            if args[1] == "HEAD":
                return TRUSTED
            if args[1].endswith("^{commit}"):
                return COMMIT
            return "d" * 40 if self.moved else ANNOTATION
        if args[0] == "show":
            name = "pdf2md-obscura-worker" if "crates/" in args[1] else "pdf2md-mcp"
            return f'[package]\nname = "{name}"\nversion = "{self.version}"\n'
        self.fail("unexpected git arguments")

    def identity(self):
        with patch.object(release, "api", side_effect=[self.remote, self.annotation]), patch.object(release, "git", side_effect=self.git):
            return release.source_identity(self.info)

    def test_annotated_main_ancestor_source_versions_and_build_suffix(self):
        result = self.identity()
        self.assertEqual(result[:3], (COMMIT, ANNOTATION, TRUSTED))
        self.assertEqual(result[3]["pdf2md-mcp"], "0.1.0")
        self.assertIn(("merge-base", "--is-ancestor", COMMIT, "refs/remotes/origin/main"), self.calls)
        self.assertTrue(any(call[0] == "show" and call[1].startswith(COMMIT + ":") for call in self.calls))

    def test_rejects_lightweight_nested_or_moved_tags(self):
        self.remote["object"]["type"] = "commit"
        with self.assertRaisesRegex(ValueError, "annotated"):
            self.identity()
        self.remote["object"]["type"] = "tag"
        self.annotation["object"]["type"] = "tag"
        with self.assertRaisesRegex(ValueError, "directly"):
            self.identity()
        self.annotation["object"]["type"] = "commit"
        self.moved = True
        with self.assertRaisesRegex(ValueError, "changed"):
            self.identity()

    def test_rejects_non_main_source_mismatched_versions_and_build_suffix(self):
        self.fail_ancestry = True
        with self.assertRaises(ValueError):
            self.identity()
        self.fail_ancestry = False
        self.version = "0.2.0"
        with self.assertRaisesRegex(ValueError, "Cargo package versions"):
            self.identity()
        self.version = "0.1.0"
        self.info["commit_prefix"] = "bbbbbbbb"
        with self.assertRaisesRegex(ValueError, "suffix"):
            self.identity()

    def test_beta_requires_exact_prerelease_package_version(self):
        self.info = release.parse_tag("0.1.0-beta.1")
        self.annotation["tag"] = self.info["tag"]
        with self.assertRaisesRegex(ValueError, "Cargo package versions"):
            self.identity()
        self.version = "0.1.0-beta.1"
        self.assertEqual(self.identity()[3]["pdf2md-mcp"], self.version)

    def test_resolve_binds_event_source_and_writes_exact_lock_data(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            event = Path(temporary) / "event.json"
            event.write_text(json.dumps({"repository": {"full_name": release.REPOSITORY}}))
            environment = {"GITHUB_EVENT_PATH": str(event), "GITHUB_EVENT_NAME": "workflow_dispatch",
                           "GITHUB_REPOSITORY": release.REPOSITORY, "GITHUB_REF": "refs/heads/main", "RELEASE_TAG": TAG}
            with patch.object(release, "release_state", return_value=None), patch.object(release, "source_identity", return_value=(COMMIT, ANNOTATION, TRUSTED, {"pdf2md-mcp": "0.1.0"})), patch.object(release, "ci_identity", return_value={"run_id": 10}), patch.object(release, "git", return_value="version = 4"):
                plan, lock = release.resolve(environment)
            self.assertEqual(plan["revision"], COMMIT)
            self.assertEqual(plan["trusted_revision"], TRUSTED)
            self.assertEqual(plan["image"], release.IMAGE)
            self.assertEqual(lock, "version = 4")
            self.assertEqual(plan["source_cargo_lock_sha256"], hashlib.sha256(lock.encode()).hexdigest())

    def test_git_show_preserves_exact_file_bytes(self):
        source = b"\nversion = 4\n\n"
        with patch.object(release, "run", return_value=(0, source, b"")):
            self.assertEqual(release.git("show", COMMIT + ":Cargo.lock").encode(), source)

    def test_output_values_are_fixed_validated_identities(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            output = Path(temporary) / "output"
            plan = {"revision": COMMIT, "tag_object_sha": ANNOTATION,
                    "ci": {"run_id": 10, "run_attempt": 2, "artifacts": {"amd64": {"id": 101}, "arm64": {"id": 102}}}}
            with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}):
                release.write_outputs(plan)
            self.assertIn("amd64_artifact_id=101\n", output.read_text())
            self.assertNotIn("tag=", output.read_text())


if __name__ == "__main__":
    unittest.main()
