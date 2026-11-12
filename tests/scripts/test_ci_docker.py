"""Offline checks for CI Docker readiness and its cleanup behavior."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("verify_docker", ROOT / "scripts/ci/verify-docker.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
IMAGE = "postgres:18@sha256:" + "a" * 64
INFO = {"SecurityOptions": ["name=rootless"], "DockerRootDir": "/tmp/docker",
        "CgroupVersion": "2", "CgroupDriver": "systemd", "CpuCfsQuota": True,
        "MemoryLimit": True, "PidsLimit": True}


class DockerReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.env = patch.dict(os.environ, {"PDF2MD_POSTGRES_IMAGE": IMAGE,
                              "PDF2MD_CI_DIAGNOSTICS_DIR": self.temp.name})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.calls = []
        self.info = INFO.copy()
        self.output = "50000 100000\n67108864\n64\n"
        self.fail = {}
        self.runner = patch.object(probe.subprocess, "run", side_effect=self.run_command)
        self.runner.start()
        self.addCleanup(self.runner.stop)

    def run_command(self, args, **kwargs):
        self.calls.append((args, kwargs))
        operation = args[1]
        if operation in self.fail:
            error = self.fail[operation]
            if error == "timeout":
                raise subprocess.TimeoutExpired(args, kwargs["timeout"])
            return subprocess.CompletedProcess(args, 1, "secret stdout", "secret stderr")
        output = json.dumps(self.info) if operation == "info" else self.output if operation == "run" else ""
        return subprocess.CompletedProcess(args, 0, output, "")

    def test_success_checks_container_and_cleans_up(self):
        self.assertEqual(probe.run_probe(), ("success", "success"))
        run = self.calls[1][0]
        for arg in ("--network", "none", "--cpus=0.5", "--memory=64m", "--pids-limit=64", "--entrypoint", "sh", IMAGE):
            self.assertIn(arg, run)
        self.assertIn("/sys/fs/cgroup/cpu.max", run[-1])
        self.assertEqual(self.calls[2][0][-1], run[3])
        self.assertIn("--volumes", self.calls[2][0])
        self.assertTrue(all(call[1]["timeout"] > 0 for call in self.calls))

    def test_rejects_metadata_before_launch(self):
        for key, value, expected in (("SecurityOptions", [], "not_rootless"),
                                     ("DockerRootDir", "/var/lib/docker", "invalid_data_root"),
                                     ("CgroupVersion", "1", "invalid_cgroup_version"),
                                     ("CgroupDriver", "cgroupfs", "invalid_cgroup_driver"),
                                     ("CpuCfsQuota", False, "missing_resource_controls"),
                                     ("MemoryLimit", False, "missing_resource_controls"),
                                     ("PidsLimit", False, "missing_resource_controls")):
            with self.subTest(key=key):
                self.info = {**INFO, key: value}
                self.calls.clear()
                self.assertEqual(probe.run_probe(), (expected, "not_attempted"))
                self.assertEqual(len(self.calls), 1)

    def test_resolves_data_root_symlink(self):
        link = Path(self.temp.name) / "outside"
        link.symlink_to("/var")
        self.info["DockerRootDir"] = str(link / "docker")
        self.assertEqual(probe.run_probe()[0], "invalid_data_root")

    def test_ignored_or_malformed_limits_fail_and_cleanup(self):
        for value in ("max 100000\n67108864\n64\n", "100000 100000\n67108864\n64\n",
                      "50000 100000\nmax\n64\n", "50000 100000\n67108864\nmax\n", "bad"):
            with self.subTest(value=value):
                self.output = value
                self.assertEqual(probe.run_probe(), ("limits_not_enforced", "success"))

    def test_launch_failure_and_timeout_still_clean_up(self):
        for error, expected in (("timeout", "command_timeout"), ("failure", "command_failed")):
            with self.subTest(error=error):
                self.fail = {"run": error}
                self.assertEqual(probe.run_probe(), (expected, "success"))

    def test_cleanup_failure_preserves_primary_and_fails_success(self):
        self.fail = {"rm": "failure"}
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(probe.main(), 1)
        self.assertEqual(json.loads((Path(self.temp.name) / "docker-readiness.json").read_text()),
                         {"probe": "success", "cleanup": "failure"})
        self.fail["run"] = "timeout"
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(probe.main(), 1)
        self.assertIn("command_timeout", stderr.getvalue())
        self.assertIn("cleanup failed", stderr.getvalue())
        self.assertNotIn("secret", stderr.getvalue())
        self.assertEqual(json.loads((Path(self.temp.name) / "docker-readiness.json").read_text()),
                         {"probe": "command_timeout", "cleanup": "failure"})

    def test_interrupted_launch_writes_diagnostics_and_preserves_exit(self):
        for interruption, code in ((KeyboardInterrupt(), 130), (SystemExit(143), 143)):
            for cleanup_failure in (False, True):
                with self.subTest(code=code, cleanup_failure=cleanup_failure):
                    self.calls.clear()
                    self.fail = {"rm": "failure"} if cleanup_failure else {}
                    def interrupted(args, **kwargs):
                        if args[1] == "run":
                            raise interruption
                        return self.run_command(args, **kwargs)
                    with patch.object(probe.subprocess, "run", side_effect=interrupted):
                        with contextlib.redirect_stderr(io.StringIO()) as stderr:
                            self.assertEqual(probe.main(), code)
                    self.assertEqual(self.calls[-1][0][1], "rm")
                    self.assertEqual(json.loads((Path(self.temp.name) / "docker-readiness.json").read_text()),
                                     {"probe": "interrupted", "cleanup": "failure" if cleanup_failure else "success"})
                    if cleanup_failure:
                        self.assertIn("cleanup failed", stderr.getvalue())

    def test_interrupted_info_writes_diagnostics(self):
        with patch.object(probe.subprocess, "run", side_effect=KeyboardInterrupt):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(probe.main(), 130)
        self.assertEqual(json.loads((Path(self.temp.name) / "docker-readiness.json").read_text()),
                         {"probe": "interrupted", "cleanup": "not_attempted"})

    def test_rejects_malformed_info_and_missing_docker(self):
        for value in ([], None):
            with self.subTest(value=value):
                self.info = value
                self.assertEqual(probe.run_probe(), ("invalid_info", "not_attempted"))
        with patch.object(probe.subprocess, "run", side_effect=FileNotFoundError("secret")):
            self.assertEqual(probe.run_probe(), ("command_unavailable", "not_attempted"))

    def test_diagnostics_outside_tmp_fails_without_exposing_output(self):
        self.fail = {"run": "failure"}
        with patch.dict(os.environ, {"PDF2MD_CI_DIAGNOSTICS_DIR": "/var/tmp/pdf2md-ci"}):
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(probe.main(), 1)
        self.assertIn("diagnostics could not be written", stderr.getvalue())
        self.assertIn("command_failed", stderr.getvalue())
        self.assertNotIn("secret", stderr.getvalue())

    def test_requires_digest_pinned_image(self):
        with patch.dict(os.environ, {"PDF2MD_POSTGRES_IMAGE": "postgres:latest"}):
            self.assertEqual(probe.run_probe(), ("invalid_image", "not_attempted"))
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
