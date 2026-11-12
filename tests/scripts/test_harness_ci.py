"""Regression checks for CI harness controls; no Docker or cluster required."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from ci import minikube


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


oidc = load("oidc_harness", "scripts/test-http-oidc.py")
fixture = load("https_fixture", "scripts/ci/fixture/server.py")
cli = load("cli_harness", "scripts/test-cli-docker.py")


class HarnessControls(unittest.TestCase):
    def test_sigterm_runs_finally_cleanup_and_preserves_exit_status(self):
        with patch.object(minikube.signal, "signal") as register:
            minikube.install_shutdown()
        register.assert_called_once()
        signum, handler = register.call_args.args
        self.assertEqual(signum, minikube.signal.SIGTERM)
        actions = []
        with self.assertRaises(SystemExit) as cancelled:
            try:
                handler(signum, None)
            finally:
                minikube.cleanup("cancelled profile", lambda: actions.append("removed"))
        self.assertEqual(cancelled.exception.code, 143)
        self.assertEqual(actions, ["removed"])

    def test_cli_docker_timeout_removes_named_container_and_preserves_timeout(self):
        commands = []
        def run(command, **kwargs):
            commands.append((command, kwargs))
            if command[1] == "run":
                raise subprocess.TimeoutExpired(command, kwargs["timeout"])
            if command[1:3] == ["container", "ls"]:
                name = commands[0][0][commands[0][0].index("--name") + 1]
                return subprocess.CompletedProcess(command, 0, name + "\n", "")
            return subprocess.CompletedProcess(command, 0, "", "")
        with patch.object(cli.subprocess, "run", side_effect=run):
            with self.assertRaises(subprocess.TimeoutExpired) as failed:
                cli.invoke(["docker", "run", "--rm", "example", "scan"])
        self.assertEqual(failed.exception.timeout, 120)
        self.assertIn("--name", commands[0][0])
        self.assertEqual(commands[-1][0][:3], ["docker", "rm", "--force"])

    def test_cli_cleanup_failure_does_not_mask_command_failure(self):
        def run(command, **kwargs):
            if command[1] == "run":
                raise subprocess.TimeoutExpired(command, kwargs["timeout"])
            raise OSError("daemon unavailable")
        output = io.StringIO()
        with patch.object(cli.subprocess, "run", side_effect=run), contextlib.redirect_stderr(output):
            with self.assertRaises(subprocess.TimeoutExpired):
                cli.invoke(["docker", "run", "--rm", "example", "scan"])
        self.assertIn("cleanup failed or is unconfirmed", output.getvalue())
        self.assertNotIn("daemon unavailable", output.getvalue())

    def test_minikube_pins_are_explicit_without_changing_standalone_defaults(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(any(a.startswith("--kubernetes-version") for a in minikube.start_args(["minikube"])))
        with patch.dict(os.environ, {"PDF2MD_TEST_KUBERNETES_VERSION": "v1.37.0", "PDF2MD_MINIKUBE_BASE_IMAGE": "node@sha256:example"}, clear=True):
            command = minikube.start_args(["minikube", "--profile", "isolated"])
            self.assertIn("--kubernetes-version=v1.37.0", command)
            self.assertIn("--base-image=node@sha256:example", command)
            self.assertIn("--container-runtime=containerd", command)
        with patch.dict(os.environ, {"PDF2MD_TEST_KUBERNETES_VERSION": "stable"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "exact Kubernetes"):
                minikube.start_args(["minikube"])

    def test_cleanup_attempts_every_action_and_fails_when_unconfirmed(self):
        actions = []
        def fail():
            actions.append("first")
            raise OSError("private command response")
        with self.assertRaisesRegex(RuntimeError, "cleanup failed or is unconfirmed"):
            minikube.cleanup("profile", fail, lambda: actions.append("second"))
        self.assertEqual(actions, ["first", "second"])

    def test_cleanup_preserves_primary_failure_and_sanitizes_secondary_failure(self):
        output = io.StringIO()
        def fail():
            raise OSError("private command response")
        with contextlib.redirect_stderr(output):
            with self.assertRaisesRegex(ValueError, "primary"):
                try:
                    raise ValueError("primary")
                finally:
                    minikube.cleanup("profile", fail)
        self.assertIn("cleanup failed", output.getvalue())
        self.assertNotIn("private", output.getvalue())

    def test_running_image_mismatch_and_missing_identity_fail(self):
        for identities in ([], [{"name": "api", "imageID": "sha256:other"}]):
            result = {"items": [{"metadata": {}, "status": {"containerStatuses": identities}}]}
            with self.assertRaisesRegex(RuntimeError, "image config digest"):
                minikube.verify_image(lambda *_args: json.dumps(result), "app=api", "api", "sha256:expected")

    def test_fixture_route_must_be_local_before_starting_https(self):
        for route in ([{"dev": "eth0", "type": "unicast"}], []):
            with patch.object(fixture.subprocess, "check_output", return_value=json.dumps(route).encode()):
                with self.assertRaisesRegex(RuntimeError, "Pod-local"):
                    fixture.local_route()
        with patch.object(fixture.subprocess, "check_output", return_value=b'[{"dev":"lo","type":"local"}]'):
            fixture.local_route()

    def test_fixture_configuration_and_permissions_preserve_production_policy(self):
        self.assertIn("rfc-editor.org", oidc.config("jwt"))
        self.assertIn('url = "https://fixture.example/sample.pdf"', oidc.config("jwt", "fixture"))
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="pdf2md-harness-unit-") as directory:
            root = Path(directory)
            for name in ("tls.crt", "tls.key", "ca.crt", "users.yml", "configuration.yml", "client-secret", "fixture.crt", "fixture.key", "sample.pdf"):
                (root / name).write_bytes(b"synthetic")
            with patch.dict(os.environ, {"PDF2MD_FIXTURE_IMAGE": "fixture:local"}):
                items = json.loads(oidc.resources(root, "api:local", "fixture").read_text())["items"]
            pod = next(item for item in items if item["kind"] == "Deployment")["spec"]["template"]["spec"]
            self.assertEqual(pod["securityContext"]["runAsUser"], 10001)
            route = pod["initContainers"][0]
            self.assertEqual(route["securityContext"]["capabilities"]["add"], ["NET_ADMIN"])
            self.assertFalse(route["securityContext"]["runAsNonRoot"])
            api = next(c for c in pod["containers"] if c["name"] == "api")
            self.assertNotIn("securityContext", api)
            self.assertEqual(api["env"], [{"name": "SSL_CERT_FILE", "value": "/config/ca.crt"}])
            fixture_secret = next(item for item in items if item.get("metadata", {}).get("name") == "https-fixture")
            self.assertNotIn("client-secret", fixture_secret["data"])
            self.assertEqual(pod["hostAliases"][0]["hostnames"], ["fixture.example"])

    def test_prebuilt_browser_zero_tests_is_a_failure_without_cargo_fallback(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="pdf2md-browser-unit-") as directory:
            fake = Path(directory) / "fake-tests"
            fake.write_text('#!/bin/sh\nprintf "test result: ok. 0 passed; 0 failed;\\n"\n')
            fake.chmod(0o755)
            env = os.environ | {"PDF2MD_BROWSER_TEST_EXECUTABLE": str(fake), "PDF2MD_TEST_WORKER": str(fake)}
            result = subprocess.run(["bash", "scripts/test-browser.sh"], cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("browser integration tests did not run", result.stderr)

    def test_prebuilt_authelia_missing_or_zero_tests_fails_before_provider_start(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="pdf2md-provider-unit-") as directory:
            fake = Path(directory) / "fake-tests"
            fake.write_text('#!/bin/sh\nprintf "0 tests, 0 benchmarks\\n"\n')
            fake.chmod(0o755)
            for executable in (str(fake), str(fake) + "-missing"):
                result = subprocess.run([sys.executable, "scripts/test-authelia.py"], cwd=ROOT,
                                        env=os.environ | {"PDF2MD_LIVE_AUTHELIA_TEST_EXECUTABLE": executable},
                                        capture_output=True, text=True, timeout=30)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("prebuilt Authelia", result.stdout)


if __name__ == "__main__":
    unittest.main()
