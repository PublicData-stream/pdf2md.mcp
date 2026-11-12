"""Offline checks for native CI dependency installation and ripgrep readiness.

Run: PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/scripts -p test_ci_native_dependencies.py
"""

import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]


class NativeDependenciesTest(unittest.TestCase):
    def setUp(self):
        action = (ROOT / ".github/actions/ci-setup/action.yml").read_text()
        match = re.search(
            r"(?ms)^    - name: Install native dependencies\n(.*?)(?=^    - name:|\Z)",
            action,
        )
        self.assertIsNotNone(match)
        self.step = match.group(1)
        run = re.search(r"(?ms)^      run: \|\n(.*)\Z", self.step)
        self.assertIsNotNone(run)
        self.script = textwrap.dedent(run.group(1))
        temp = tempfile.TemporaryDirectory(prefix="pdf2md-ci-dependencies-", dir="/tmp")
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.log = self.base / "commands"
        self.env = os.environ.copy()
        self.env.update({"PATH": str(self.base), "TMPDIR": "/tmp",
                         "MOCK_LOG": str(self.log), "MOCK_FAIL": ""})
        self.write_command("sudo", '''#!/bin/bash
set -eu
printf '%s\\n' "$*" >> "$MOCK_LOG"
[[ $1 == apt-get ]]
if [[ ${MOCK_FAIL-} == "$2" ]]; then exit 23; fi
''')
        self.write_command("rg", '''#!/bin/bash
set -eu
printf 'rg %s\\n' "$*" >> "$MOCK_LOG"
if [[ $1 == --version ]]; then
    if [[ ${MOCK_FAIL-} == version ]]; then exit 24; fi
    printf 'ripgrep mock\\n'
else
    if [[ ${MOCK_FAIL-} == search ]]; then exit 25; fi
    IFS= read -r line
    [[ $* == '--no-config --fixed-strings --quiet pdf2md-ci-ripgrep-probe' ]]
    [[ $line == pdf2md-ci-ripgrep-probe ]]
fi
''')

    def write_command(self, name, content):
        path = self.base / name
        path.write_text(content)
        path.chmod(0o755)

    def run_step(self):
        return subprocess.run(["/bin/bash", "--noprofile", "--norc", "-eo", "pipefail",
                               "-c", self.script], env=self.env, text=True,
                              capture_output=True, check=False)

    def test_rust_jobs_install_ripgrep_and_execute_search_before_compilation(self):
        self.assertIn("      if: inputs.rust == 'true'\n", self.step)
        self.assertIn("      shell: bash\n", self.step)
        result = self.run_step()
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = self.log.read_text().splitlines()
        self.assertEqual(commands[0], "apt-get update")
        self.assertEqual(commands[1].split()[:2], ["apt-get", "install"])
        self.assertIn("ripgrep", commands[1].split()[2:])
        self.assertEqual(commands[2:], ["rg --version",
                         "rg --no-config --fixed-strings --quiet pdf2md-ci-ripgrep-probe"])

    def test_installation_and_probe_failures_stop_dependency_setup(self):
        for failure, code, count in (("update", 23, 1), ("install", 23, 2),
                                     ("version", 24, 3), ("search", 25, 4)):
            with self.subTest(failure=failure):
                self.log.write_text("")
                self.env["MOCK_FAIL"] = failure
                result = self.run_step()
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertEqual(len(self.log.read_text().splitlines()), count)

    def test_missing_ripgrep_fails_dependency_setup(self):
        (self.base / "rg").unlink()
        result = self.run_step()
        self.assertEqual(result.returncode, 127, result.stderr)
        self.assertIn("rg: command not found", result.stderr)


if __name__ == "__main__":
    unittest.main()
