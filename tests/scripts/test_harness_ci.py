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
from unittest.mock import Mock, patch

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
    def test_oidc_provider_listener_probe_is_present_in_both_modes(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            for name in ("tls.crt", "tls.key", "ca.crt", "client-secret", "fixture.crt", "fixture.key", "sample.pdf", "import/pdf2md.json"):
                (root / name).parent.mkdir(exist_ok=True)
                (root / name).write_bytes(b"synthetic")
            for mode in ("live", "fixture"):
                with self.subTest(mode=mode), patch.dict(os.environ, {"PDF2MD_FIXTURE_IMAGE": "fixture:local"}):
                    items = json.loads(oidc.resources(root, "api:local", mode).read_text())["items"]
                    pod = next(item for item in items if item["kind"] == "Deployment")["spec"]["template"]["spec"]
                    provider = next(container for container in pod["containers"] if container["name"] == "provider")
                    self.assertEqual(provider["readinessProbe"], {"httpGet": {"scheme": "HTTPS", "path": "/realms/pdf2md/.well-known/openid-configuration", "port": 9091}, "periodSeconds": 5, "timeoutSeconds": 3})
                    self.assertIn("--hostname=https://127.0.0.1:9091", provider["args"])
                    mounts = {mount["name"]: mount["mountPath"] for mount in provider["volumeMounts"]}
                    self.assertEqual(mounts["provider-realm"], "/opt/keycloak/data/import")
                    realm = next(item for item in items if item.get("metadata", {}).get("name") == "provider-realm")
                    self.assertEqual(set(realm["data"]), {"pdf2md.json"})

    def test_oidc_readiness_retries_both_checks_and_bounds_timeouts(self):
        now = [0.0]
        control = Mock()
        control.request.side_effect = [OSError("private"), (200, {}, {"issuer": oidc.ISSUER})]
        forward = Mock()
        forward.poll.return_value = None
        startup = oidc.Startup()
        with patch.object(oidc.time, "monotonic", side_effect=lambda: now[0]), \
             patch.object(oidc.time, "sleep", side_effect=lambda seconds: now.__setitem__(0, now[0] + seconds)), \
             patch.object(oidc, "api", side_effect=[(503, b""), (200, b"")]) as api:
            oidc.ready("http://localhost", control, forward, startup, timeout=1)
        self.assertEqual((startup.provider, startup.api), ("ready", "ready"))
        self.assertEqual(control.request.call_count, 2)
        self.assertEqual(api.call_count, 2)
        self.assertTrue(all(0 < call.kwargs["timeout"] <= 1 for call in control.request.call_args_list + api.call_args_list))

    def test_oidc_readiness_requires_both_successes_in_same_iteration(self):
        now = [0.0]
        control = Mock()
        control.request.side_effect = [(200, {}, {"issuer": oidc.ISSUER}), (503, {}, None)]
        forward = Mock()
        forward.poll.return_value = None
        startup = oidc.Startup()
        with patch.object(oidc.time, "monotonic", side_effect=lambda: now[0]), \
             patch.object(oidc.time, "sleep", side_effect=lambda seconds: now.__setitem__(0, now[0] + seconds)), \
             patch.object(oidc, "api", side_effect=[(503, b""), (200, b"")]):
            with self.assertRaisesRegex(RuntimeError, "readiness timeout"):
                oidc.ready("http://localhost", control, forward, startup, timeout=1)
        self.assertEqual((startup.provider, startup.api), ("unexpected_http_status", "ready"))

    def test_oidc_readiness_classifies_independent_failures(self):
        cases = [
            ((503, {}, None), OSError("private"), "unexpected_http_status", "connection_failure"),
            ((200, {}, None), TimeoutError("private"), "invalid_discovery", "timeout"),
            ((200, {}, {"issuer": "wrong"}), (503, b""), "issuer_mismatch", "unexpected_http_status"),
            (oidc.urllib.error.URLError(oidc.ssl.SSLCertVerificationError("private")), (200, b""), "tls_verification_failure", "ready"),
        ]
        for provider_result, api_result, provider_state, api_state in cases:
            with self.subTest(provider_state=provider_state):
                now = [0.0]
                control, forward, startup = Mock(), Mock(), oidc.Startup()
                forward.poll.return_value = None
                control.request.side_effect = provider_result if isinstance(provider_result, Exception) else None
                control.request.return_value = provider_result
                with patch.object(oidc.time, "monotonic", side_effect=lambda: now[0]), \
                     patch.object(oidc.time, "sleep", side_effect=lambda seconds: now.__setitem__(0, now[0] + seconds)), \
                     patch.object(oidc, "api", side_effect=api_result if isinstance(api_result, Exception) else None, return_value=api_result):
                    with self.assertRaisesRegex(RuntimeError, "readiness timeout") as error:
                        oidc.ready("http://localhost", control, forward, startup, timeout=0.5)
                self.assertEqual((startup.provider, startup.api), (provider_state, api_state))
                self.assertNotIn("private", str(error.exception))

    def test_oidc_forward_exit_is_detected_before_and_during_probes(self):
        for code in (0, 7, -15):
            for poll_results in ([code], [None, code], [None, None, code]):
                with self.subTest(code=code, poll_results=poll_results):
                    control, forward, startup = Mock(), Mock(), oidc.Startup()
                    forward.poll.side_effect = poll_results
                    control.request.return_value = (200, {}, {"issuer": oidc.ISSUER})
                    with patch.object(oidc, "api", return_value=(200, b"")):
                        with self.assertRaisesRegex(RuntimeError, "port-forward exited"):
                            oidc.ready("http://localhost", control, forward, startup, timeout=1)
                    self.assertEqual(startup.forward_exit_code, code)

    def test_oidc_provider_deadline_exhaustion_does_not_run_api(self):
        now = [0.0]
        control, forward, startup = Mock(), Mock(), oidc.Startup()
        forward.poll.return_value = None
        def slow_request(_path, *, timeout):
            now[0] += timeout
            return 200, {}, {"issuer": oidc.ISSUER}
        control.request.side_effect = slow_request
        with patch.object(oidc.time, "monotonic", side_effect=lambda: now[0]), \
             patch.object(oidc.time, "sleep"), patch.object(oidc, "api") as api:
            with self.assertRaisesRegex(RuntimeError, "readiness timeout"):
                oidc.ready("http://localhost", control, forward, startup, timeout=1)
        api.assert_not_called()
        self.assertEqual(startup.api, "not_checked")

    def test_oidc_diagnostics_only_write_allowlisted_container_status(self):
        pod = {"status": {"containerStatuses": [
            {"name": "provider", "ready": True, "restartCount": 2, "state": {"terminated": {"exitCode": 1, "signal": 9, "message": "private"}}, "image": "private"},
            {"name": "unknown-private", "state": {"waiting": {"message": "private"}}},
        ]}, "spec": {"secret": "private"}}
        startup = oidc.Startup("jwt")
        startup.stage, startup.provider, startup.api, startup.forward_exit_code = "readiness", "issuer_mismatch", "ready", -15
        with tempfile.TemporaryDirectory(dir="/tmp") as directory, patch.dict(os.environ, {"PDF2MD_CI_DIAGNOSTICS_DIR": directory}):
            kube = Mock(return_value=json.dumps({"items": [pod]}))
            startup.diagnose(kube)
            result = json.loads((Path(directory) / "oidc-startup.json").read_text())
        self.assertEqual(result, {"phase": "jwt", "stage": "readiness", "provider": "issuer_mismatch", "api": "ready", "forward_exit_code": -15,
                                  "containers": [{"name": "provider", "ready": True, "state": "terminated", "restarts": 2, "exitCode": 1, "signal": 9}]})
        self.assertEqual(kube.call_args.kwargs["timeout"], 10)

    def test_oidc_diagnostic_failures_do_not_mask_primary_or_cleanup(self):
        for destination in ("valid", "outside"):
            actions, output = [], io.StringIO()
            with tempfile.TemporaryDirectory(dir="/tmp") as directory, \
                 patch.dict(os.environ, {"PDF2MD_CI_DIAGNOSTICS_DIR": directory if destination == "valid" else "/var/tmp/private"}), \
                 contextlib.redirect_stderr(output):
                with self.assertRaisesRegex(ValueError, "primary"):
                    try:
                        raise ValueError("primary")
                    except ValueError:
                        oidc.Startup().diagnose(Mock(side_effect=OSError("private")))
                        raise
                    finally:
                        minikube.cleanup("profile", lambda: actions.append("cleaned"))
                if destination == "valid":
                    self.assertEqual(json.loads((Path(directory) / "oidc-startup.json").read_text())["containers_status"], "unavailable")
                else:
                    self.assertIn("diagnostics could not be written", output.getvalue())
            self.assertEqual(actions, ["cleaned"])
            self.assertNotIn("private", output.getvalue())

    def test_oidc_rollout_failure_diagnoses_phase_before_failed_cleanup(self):
        for failed_phase in ("initial", "jwt"):
            with self.subTest(phase=failed_phase), tempfile.TemporaryDirectory(dir="/tmp") as directory:
                events = []
                rollout_count = [0]
                digest = "sha256:" + "a" * 64
                def invoke(args, **_kwargs):
                    if args[:3] == ["docker", "image", "inspect"]:
                        return digest
                    if args[:2] == ["docker", "info"]:
                        return '["name=rootless"]' if "{{json .SecurityOptions}}" in args else "/tmp/docker"
                    if "rollout" in args and "status" in args:
                        rollout_count[0] += 1
                        if rollout_count[0] == (1 if failed_phase == "initial" else 2):
                            raise RuntimeError("primary rollout failure")
                    if "pods" in args and "json" in args:
                        events.append("diagnose" if rollout_count[0] == (1 if failed_phase == "initial" else 2) else "verify")
                        return json.dumps({"items": [{"metadata": {}, "status": {"containerStatuses": [{"name": "api", "imageID": digest, "ready": True}]}}]})
                    return ""
                def failed_cleanup(*_args, **_kwargs):
                    report = json.loads((Path(directory) / "oidc-startup.json").read_text())
                    self.assertEqual((report["phase"], report["stage"]), (failed_phase, "rollout"))
                    events.append("cleanup")
                    raise OSError("private cleanup failure")
                proc = Mock()
                socket_handle = Mock()
                socket_handle.__enter__ = Mock(return_value=socket_handle)
                socket_handle.__exit__ = Mock(return_value=False)
                socket_handle.getsockname.return_value = ("127.0.0.1", 12345)
                stderr = io.StringIO()
                with patch.dict(os.environ, {"PDF2MD_CI_DIAGNOSTICS_DIR": directory, "PDF2MD_EXPECTED_IMAGE_CONFIG_DIGEST": digest}), \
                     patch.object(sys, "argv", ["test-http-oidc.py", "api:local"]), \
                     patch.object(oidc, "install_shutdown"), patch.object(oidc, "invoke", side_effect=invoke), \
                     patch.object(oidc, "generate", return_value=({"alice": "password", "bob": "password"}, "secret")), \
                     patch.object(oidc, "resources", return_value=Path(directory) / "resources.json"), \
                     patch.object(oidc.provider, "Client"), patch.object(oidc, "ready"), \
                     patch.object(oidc, "run_test", return_value=("document", "job", True)), \
                     patch.object(oidc.socket, "socket", return_value=socket_handle), \
                     patch.object(oidc.subprocess, "Popen", return_value=proc), \
                     patch.object(oidc, "checked_cleanup", side_effect=failed_cleanup), \
                     contextlib.redirect_stderr(stderr):
                    with self.assertRaisesRegex(RuntimeError, "primary rollout failure"):
                        oidc.main()
                self.assertEqual(events[-2:], ["diagnose", "cleanup"])
                self.assertIn("cleanup failed or is unconfirmed", stderr.getvalue())
                self.assertNotIn("private cleanup failure", stderr.getvalue())

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
            for name in ("tls.crt", "tls.key", "ca.crt", "client-secret", "fixture.crt", "fixture.key", "sample.pdf", "import/pdf2md.json"):
                (root / name).parent.mkdir(exist_ok=True)
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

    def test_prebuilt_keycloak_missing_or_zero_tests_fails_before_provider_start(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="pdf2md-provider-unit-") as directory:
            fake = Path(directory) / "fake-tests"
            fake.write_text('#!/bin/sh\nprintf "0 tests, 0 benchmarks\\n"\n')
            fake.chmod(0o755)
            for executable in (str(fake), str(fake) + "-missing"):
                result = subprocess.run([sys.executable, "scripts/test-keycloak.py"], cwd=ROOT,
                                        env=os.environ | {"PDF2MD_LIVE_KEYCLOAK_TEST_EXECUTABLE": executable},
                                        capture_output=True, text=True, timeout=30)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("prebuilt Keycloak", result.stdout)


if __name__ == "__main__":
    unittest.main()
