"""Offline checks for the rootless Docker user-session setup.

Run: PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/scripts -p test_ci_docker_session.py
"""
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SETUP = ROOT / "scripts/ci/setup-docker-session.sh"


class DockerSessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pdf2md-docker-session-", dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.runtime = self.root / "runtime"
        self.runtime.mkdir(mode=0o700)
        self.bus = socket.socket(socket.AF_UNIX)
        self.bus.bind(str(self.runtime / "bus"))
        self.addCleanup(self.bus.close)
        self.environment = self.root / "environment"
        self.environment.touch()
        self.log = self.root / "commands"
        stub = self.bin / "stub"
        stub.write_text('''#!/bin/bash
set -eu
name=${0##*/}
printf '%s|%s|%s|%s\\n' "$name" "$*" "${XDG_RUNTIME_DIR-}" "${DBUS_SESSION_BUS_ADDRESS-}" >> "$MOCK_LOG"
if [[ ${MOCK_FAIL-} == "$name $*" ]]; then exit 23; fi
case "$name" in
  sudo) shift; exec "$@" ;;
  id) printf '%s\\n' "${MOCK_UID}" ;;
  loginctl)
    if [[ $1 == show-user ]]; then printf '%s\\n' "$MOCK_RUNTIME"; fi ;;
  systemctl)
    if [[ $1 == show ]]; then printf '%s\\n' "${MOCK_CGROUP:-/user.slice/user-test.slice/user@test.service}"; fi
    if [[ $* == '--user show-environment' ]]; then echo SENTINEL_SESSION_SECRET; fi ;;
  cat) printf '%s\\n' "${MOCK_CONTROLLERS-cpu cpuset io memory pids}" ;;
esac
''')
        stub.chmod(0o755)
        for name in ("sudo", "id", "loginctl", "systemctl", "cat"):
            (self.bin / name).symlink_to(stub)
        self.env = dict(os.environ, PATH=f"{self.bin}:/usr/bin:/bin",
                        GITHUB_ENV=str(self.environment), MOCK_LOG=str(self.log),
                        MOCK_RUNTIME=str(self.runtime), MOCK_UID=str(os.getuid()),
                        DBUS_SESSION_BUS_ADDRESS="unix:path=/wrong/bus", XDG_RUNTIME_DIR="/wrong")

    def run_setup(self):
        return subprocess.run(["bash", str(SETUP)], env=self.env, text=True,
                              capture_output=True, check=False)

    def test_verified_bus_is_published_after_session_and_delegation_checks(self):
        result = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stderr)
        address = f"unix:path={self.runtime}/bus"
        self.assertEqual(self.environment.read_text(), f"DBUS_SESSION_BUS_ADDRESS={address}\n")
        lines = self.log.read_text().splitlines()
        commands = [line.split("|")[:2] for line in lines]
        self.assertIn(["loginctl", f"enable-linger {os.getuid()}"], commands)
        self.assertIn(["systemctl", "--user start dbus.socket"], commands)
        for line in lines:
            if "|--user " in line:
                self.assertEqual(line.split("|")[2:], [str(self.runtime), address])
        self.assertNotIn("SENTINEL_SESSION_SECRET", result.stdout + result.stderr)
        # Only the explicit bus address is published, so the setup action can
        # use its own XDG_RUNTIME_DIR without redirecting runc to the system bus.
        next_env = dict(self.env)
        next_env.update(line.split("=", 1) for line in self.environment.read_text().splitlines())
        next_env["XDG_RUNTIME_DIR"] = str(self.root / "daemon-runtime")
        followup = subprocess.run(["systemctl", "--user", "is-active", "--quiet", "dbus.socket"],
                                  env=next_env, capture_output=True, check=False)
        self.assertEqual(followup.returncode, 0)
        self.assertEqual(self.log.read_text().splitlines()[-1].split("|")[3], address)

    def test_session_command_failures_do_not_publish_environment(self):
        for command in (
            f"loginctl enable-linger {os.getuid()}",
            f"systemctl start user@{os.getuid()}.service",
            "systemctl --user start dbus.socket", "systemctl --user is-active --quiet dbus.socket",
            "systemctl --user show-environment",
        ):
            with self.subTest(command=command):
                self.env["MOCK_FAIL"] = command
                result = self.run_setup()
                self.assertEqual(result.returncode, 23, result.stderr)
                self.assertEqual(self.environment.read_text(), "")

    def test_missing_bus_does_not_publish_environment(self):
        (self.runtime / "bus").unlink()
        result = self.run_setup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("D-Bus socket is unavailable", result.stderr)
        self.assertEqual(self.environment.read_text(), "")

    def test_runtime_directory_must_be_private_and_owned_by_runner(self):
        self.runtime.chmod(0o755)
        result = self.run_setup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("private and owned", result.stderr)
        self.assertEqual(self.environment.read_text(), "")
        self.runtime.chmod(0o700)
        self.env["MOCK_UID"] = str(os.getuid() + 1)
        result = self.run_setup()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.environment.read_text(), "")

    def test_invalid_runtime_or_cgroup_and_missing_controllers_are_rejected(self):
        for key, value in (("MOCK_RUNTIME", "/nonexistent/pdf2md-runtime"),
                           ("MOCK_RUNTIME", "/tmp\nINJECTED=value"),
                           ("MOCK_CGROUP", "/system.slice/service"),
                           ("MOCK_CGROUP", "/user.slice/../../system.slice"),
                           ("MOCK_CONTROLLERS", "memory pids")):
            with self.subTest(key=key, value=value):
                previous = self.env.get(key)
                self.env[key] = value
                result = self.run_setup()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.environment.read_text(), "")
                if previous is None:
                    del self.env[key]
                else:
                    self.env[key] = previous

    def test_root_runner_and_missing_environment_file_are_rejected(self):
        self.env["MOCK_UID"] = "0"
        self.assertNotEqual(self.run_setup().returncode, 0)
        self.assertEqual(self.environment.read_text(), "")
        self.env["MOCK_UID"] = str(os.getuid())
        del self.env["GITHUB_ENV"]
        self.assertNotEqual(self.run_setup().returncode, 0)


class DockerSessionWorkflowTests(unittest.TestCase):
    def test_session_setup_precedes_daemon_and_readiness_follows_it(self):
        text = (ROOT / ".github/actions/ci-setup/action.yml").read_text()
        names = ["Prepare rootless Docker session", "Set up rootless Docker", "Verify disposable daemon"]
        offsets = [text.index("    - name: " + name) for name in names]
        self.assertEqual(offsets, sorted(offsets))
        for name in names:
            step = re.search(r"(?ms)^    - name: " + re.escape(name) + r"\n(.*?)(?=^    - name:|\Z)", text).group(1)
            self.assertIn("if: inputs.docker == 'true'", step)
        self.assertIn("run: bash scripts/ci/setup-docker-session.sh", text)
        self.assertIn("rootless: true", text)


if __name__ == "__main__":
    unittest.main()
