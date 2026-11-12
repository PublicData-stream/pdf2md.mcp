"""Offline regression tests for the CI rustup setup.

Run: PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/scripts -p test_ci_rust.py
"""

import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SETUP = ROOT / "scripts/ci/setup-rust.sh"
PROXIES = (
    "rustup", "cargo", "rustc", "rustdoc", "rustfmt", "cargo-fmt",
    "cargo-clippy", "clippy-driver",
)


class RustSetupTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pdf2md-ci-rust-", dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "runner-bin"
        self.bin.mkdir()
        self.log = self.root / "commands"
        self.github_env = self.root / "github-env"
        self.github_path = self.root / "github-path"
        self.github_env.touch()
        self.github_path.touch()
        proxy = self.bin / "rustup"
        proxy.write_text('''#!/bin/bash
set -eu
name=${0##*/}
printf '%s|%s|%s|%s|%s|%s\\n' "$name" "$*" "${RUSTUP_TOOLCHAIN-}" "${CARGO_HOME-}" "${RUSTUP_HOME-}" "${TMPDIR-}" >> "$MOCK_LOG"
if [[ ${MOCK_FAIL-} == "$name $*" ]]; then exit 23; fi
if [[ $name == rustc && ${1-} == --version ]]; then
    printf '%s\\n' "${MOCK_VERSION:-rustc 1.99.1 (mock)}"
elif [[ $name == rustc && ${1-} == --print && ${2-} == sysroot ]]; then
    printf '%s\\n' "${MOCK_SYSROOT:-$RUSTUP_HOME/toolchains/1.99.1-mock}"
else
    printf '%s\\n' "mock $name $*"
fi
''')
        proxy.chmod(0o755)
        for name in PROXIES[1:]:
            (self.bin / name).symlink_to(proxy)
        self.home = self.root / "rustup-home"
        (self.home / "toolchains/1.99.1-mock").mkdir(parents=True)
        self.env = os.environ.copy()
        self.env.update({
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "CARGO_HOME": str(self.root / "cargo-home"),
            "RUSTUP_HOME": str(self.home),
            "GITHUB_ENV": str(self.github_env),
            "GITHUB_PATH": str(self.github_path),
            "RUSTUP_TOOLCHAIN": "old-conflicting-toolchain",
            "TMPDIR": str(self.root),
            "MOCK_LOG": str(self.log),
        })

    def run_setup(self):
        return subprocess.run(["bash", str(SETUP)], env=self.env, text=True,
                              capture_output=True, check=False)

    def assert_unpublished(self):
        self.assertEqual(self.github_env.read_text(), "")
        self.assertEqual(self.github_path.read_text(), "")

    def test_installs_pinned_toolchain_and_publishes_working_proxies(self):
        result = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = self.log.read_text().splitlines()
        commands = [line.split("|")[:2] for line in lines]
        self.assertIn(["rustup", "toolchain install 1.99.1 --profile minimal --component clippy --component rustfmt --no-self-update"], commands)
        self.assertIn(["rustup", "default 1.99.1"], commands)
        for command in (["rustup", "show active-toolchain"], ["rustc", "--version"],
                        ["rustc", "--print sysroot"], ["cargo", "--version"],
                        ["cargo", "fmt --version"], ["cargo", "clippy --version"]):
            self.assertIn(command, commands)
        for line in lines:
            self.assertEqual(line.split("|")[2:], ["1.99.1", self.env["CARGO_HOME"], str(self.home), "/tmp"])
        self.assertTrue(Path(self.env["CARGO_HOME"]).is_dir())
        self.assertEqual(self.github_env.read_text().splitlines(), ["RUSTUP_TOOLCHAIN=1.99.1"])
        self.assertEqual(self.github_path.read_text().splitlines(), [str(self.bin)])

        # Simulate the next Actions step: its environment comes from the files,
        # not from exports in the previous shell process.
        next_env = self.env.copy()
        next_env.update(line.split("=", 1) for line in self.github_env.read_text().splitlines())
        next_env["PATH"] = ":".join(self.github_path.read_text().splitlines() + ["/usr/bin", "/bin"])
        script = 'for tool in cargo rustc rustdoc rustfmt cargo-fmt cargo-clippy clippy-driver; do "$tool" --version; done'
        followup = subprocess.run(["bash", "-c", script], env=next_env, text=True,
                                  capture_output=True, check=False)
        self.assertEqual(followup.returncode, 0, followup.stderr)
        self.assertEqual([line.split("|")[0] for line in self.log.read_text().splitlines()[-7:]],
                         ["cargo", "rustc", "rustdoc", "rustfmt", "cargo-fmt", "cargo-clippy", "clippy-driver"])
        for line in self.log.read_text().splitlines()[-7:]:
            self.assertEqual(line.split("|")[2:5], ["1.99.1", self.env["CARGO_HOME"], str(self.home)])

    def test_missing_rustup_or_sibling_proxy_fails_without_publication(self):
        for name in PROXIES:
            with self.subTest(name=name):
                path = self.bin / name
                if name == "rustup":
                    path.rename(self.bin / "hidden-rustup")
                else:
                    path.unlink()
                result = self.run_setup()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(name, result.stderr.lower())
                self.assert_unpublished()
                if name == "rustup":
                    (self.bin / "hidden-rustup").rename(path)
                else:
                    path.symlink_to(self.bin / "rustup")

    def test_install_or_component_failure_preserves_exit_code_without_publication(self):
        for command in (
            "rustup toolchain install 1.99.1 --profile minimal --component clippy --component rustfmt --no-self-update",
            "rustup default 1.99.1", "cargo fmt --version", "cargo clippy --version",
        ):
            with self.subTest(command=command):
                self.env["MOCK_FAIL"] = command
                result = self.run_setup()
                self.assertEqual(result.returncode, 23, result.stderr)
                self.assert_unpublished()

    def test_wrong_compiler_version_or_sysroot_does_not_publish(self):
        outside = self.root / "outside"
        outside.mkdir()
        symlink = self.home / "toolchains/outside-link"
        symlink.symlink_to(outside, target_is_directory=True)
        for key, value, message in (
            ("MOCK_VERSION", "rustc 1.99.10 (mock)", "Unexpected Rust compiler"),
            ("MOCK_SYSROOT", str(outside), "outside the isolated RUSTUP_HOME"),
            ("MOCK_SYSROOT", str(symlink), "outside the isolated RUSTUP_HOME"),
        ):
            with self.subTest(key=key):
                self.env[key] = value
                result = self.run_setup()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assert_unpublished()
                del self.env[key]

    def test_required_environment_is_checked(self):
        for name in ("CARGO_HOME", "RUSTUP_HOME", "GITHUB_ENV", "GITHUB_PATH"):
            with self.subTest(name=name):
                value = self.env.pop(name)
                result = self.run_setup()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(name, result.stderr)
                self.assert_unpublished()
                self.env[name] = value


class RustWorkflowTest(unittest.TestCase):
    def test_no_external_rust_toolchain_action_and_conditional_helper(self):
        paths = list((ROOT / ".github/workflows").glob("*.yml"))
        paths += list((ROOT / ".github/workflows").glob("*.yaml"))
        paths += list((ROOT / ".github/actions").glob("**/action.yml"))
        paths += list((ROOT / ".github/actions").glob("**/action.yaml"))
        self.assertTrue(paths)
        for path in paths:
            with self.subTest(path=path):
                self.assertNotRegex(path.read_text(), r"(?im)^\s*(?:-\s*)?uses:\s*['\"]?dtolnay/rust-toolchain(?:@|\s)")
        action = (ROOT / ".github/actions/ci-setup/action.yml").read_text()
        match = re.search(r"(?ms)^\s*- name: Install Rust\s*\n(.*?)(?=^\s*- name:|\Z)", action)
        self.assertIsNotNone(match)
        step = match.group(1)
        self.assertRegex(step, r"(?m)^\s*if:\s*(?:\$\{\{\s*)?inputs\.rust\s*==\s*'true'(?:\s*\}\})?\s*$")
        self.assertRegex(step, r"(?m)^\s*shell:\s*bash\s*$")
        self.assertRegex(step, r"(?m)^\s*(?:run:\s*)?(?:bash\s+)?(?:\./)?scripts/ci/setup-rust\.sh\s*$")


if __name__ == "__main__":
    unittest.main()
