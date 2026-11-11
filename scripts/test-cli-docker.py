#!/usr/bin/env python3
"""Exercise local and Docker manual ingestion with disposable synthetic data."""
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

CLI = os.environ.get("PDF2MD_TEST_CLI", "/tmp/rust/target/debug/pdf2md-mcp")
IMAGE = sys.argv[1] if len(sys.argv) > 1 else "pdf2md-mcp:local"
FIRST = b"%PDF-1.7\nsynthetic first\n%%EOF\n"
SECOND = b"%PDF-1.7\nsynthetic second\n%%EOF\n"
WATCHED = b"%PDF-1.7\nsynthetic watched\n%%EOF\n"
DOCKER_USER = None


def invoke(args, expected=0, timeout=15):
    proc = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if (proc.returncode == 0) != (expected == 0):
        raise AssertionError(f"command failed expectation: {args[0]} {args[-1]}, exit={proc.returncode}, stderr={proc.stderr}")
    return proc


def observations(proc):
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def digest(value):
    return hashlib.sha256(value).hexdigest()


def wait_for(check, description, timeout=15):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if check():
                return
        except (AssertionError, ValueError, json.JSONDecodeError):
            pass
        time.sleep(0.3)
    raise AssertionError(f"timed out waiting for {description}")


def local_command(root, pg=False):
    command = [CLI, "--data-dir", str(root), "--json"]
    if pg:
        command += ["--database-url-env", "PDF2MD_TEST_POSTGRES_URL"]
    return command


def exercise_local(root, pg=False):
    # A first scan initializes the store and its manual input directory.
    cmd = local_command(root, pg)
    assert observations(invoke(cmd + ["scan"])) == []
    path = root / "pdfs" / "sample.pdf"
    path.write_bytes(FIRST)
    first = observations(invoke(cmd + ["scan"]))
    assert len(first) == 1 and first[0]["document_id"] == digest(FIRST)
    assert observations(invoke(cmd + ["scan"])) == []
    path.write_bytes(SECOND)
    second = observations(invoke(cmd + ["scan"]))
    assert len(second) == 1 and second[0]["document_id"] == digest(SECOND)
    path.write_bytes(FIRST)
    reverted = observations(invoke(cmd + ["scan"]))
    assert len(reverted) == 1 and reverted[0]["document_id"] == digest(FIRST)
    history = observations(invoke(cmd + ["history"]))
    assert [row["document_id"] for row in history] == [digest(FIRST), digest(SECOND), digest(FIRST)]
    assert len(list((root / "objects").iterdir())) == 2
    watcher = subprocess.Popen(cmd + ["watch"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        watched = root / "pdfs" / "watched.pdf"
        watched.write_bytes(WATCHED)
        def observed():
            assert watcher.poll() is None, "watch process exited"
            rows = observations(invoke(cmd + ["status"]))
            return any(row.get("document_id") == digest(WATCHED) for row in rows)
        wait_for(observed, "local watch and concurrent status")
        watcher.send_signal(signal.SIGTERM)
        _, err = watcher.communicate(timeout=10)
        assert watcher.returncode == 0, f"watch shutdown failed: {err}"
        assert not list((root / ".staging").iterdir())
    finally:
        if watcher.poll() is None:
            watcher.kill()
            watcher.wait(timeout=5)
        if watcher.stderr:
            watcher.stderr.close()
    (root / "pdfs" / "bad.pdf").write_bytes(b"this is not a PDF")
    failed = invoke(cmd + ["scan"], expected=1)
    rows = observations(failed)
    assert any(row.get("outcome") == "failed" for row in rows)
    print("PASS local " + ("PostgreSQL" if pg else "SQLite") + " scan, revision, watch, status, shutdown, invalid PDF")


def docker_run(root, *args, expected=0):
    return invoke(["docker", "run", "--rm", "--user", DOCKER_USER,
                   "--mount", f"type=bind,src={root},dst=/data", IMAGE,
                   "--data-dir", "/data", "--json", *args], expected=expected, timeout=20)


def exercise_docker(root):
    user = invoke(["docker", "image", "inspect", "--format", "{{.Config.User}}", IMAGE]).stdout.strip()
    assert user == "10001:10001", f"unexpected image user: {user!r}"
    global DOCKER_USER
    security = json.loads(invoke(["docker", "info", "--format", "{{json .SecurityOptions}}"] ).stdout)
    rootless = "name=rootless" in security
    # In rootless Docker, container UID 0 maps to the unprivileged daemon owner.
    # For a rootful daemon, use the actual host UID:GID for bind-mount access.
    DOCKER_USER = "0:0" if rootless else f"{os.getuid()}:{os.getgid()}"
    print(f"PASS image default user 10001:10001; bind-mount tests use {DOCKER_USER} (rootless={rootless})")
    smoke = root / "default-user"
    smoke.mkdir()
    mount = f"type=bind,src={smoke},dst=/data"
    restore_owner = "0:0" if rootless else f"{os.getuid()}:{os.getgid()}"
    try:
        invoke(["docker", "run", "--rm", "--user", "0:0", "--mount", mount,
                "--entrypoint", "chown", IMAGE, "10001:10001", "/data"])
        base = ["docker", "run", "--rm", "--mount", mount, IMAGE, "--data-dir", "/data", "--json"]
        assert observations(invoke(base + ["scan"])) == []
        invoke(["docker", "run", "--rm", "--mount", mount, "--entrypoint", "sh", IMAGE,
                "-c", "printf '%%PDF-1.7 default user\\n%%%%EOF\\n' > /data/pdfs/default.pdf"])
        rows = observations(invoke(base + ["scan"]))
        assert len(rows) == 1 and rows[0]["document_id"] == digest(b"%PDF-1.7 default user\n%%EOF\n")
        print("PASS Docker actual default UID 10001:10001 scan")
    finally:
        subprocess.run(["docker", "run", "--rm", "--user", "0:0", "--mount", mount,
                        "--entrypoint", "chown", IMAGE, "-R", restore_owner, "/data"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=True)
        shutil.rmtree(smoke)
    assert observations(docker_run(root, "scan")) == []
    (root / "pdfs" / "container.pdf").write_bytes(FIRST)
    rows = observations(docker_run(root, "scan"))
    assert len(rows) == 1 and rows[0]["document_id"] == digest(FIRST)
    assert observations(docker_run(root, "scan")) == []
    name = "pdf2md-validation-" + uuid.uuid4().hex
    created = False
    try:
        invoke(["docker", "run", "-d", "--name", name, "--user", DOCKER_USER,
                "--mount", f"type=bind,src={root},dst=/data", IMAGE,
                "--data-dir", "/data", "--json", "watch"])
        created = True
        (root / "pdfs" / "watched.pdf").write_bytes(WATCHED)
        def observed():
            state = invoke(["docker", "inspect", "--format", "{{.State.Running}}", name]).stdout.strip()
            assert state == "true", "container stopped"
            rows = observations(docker_run(root, "status"))
            return any(row.get("document_id") == digest(WATCHED) for row in rows)
        wait_for(observed, "container watch and concurrent status")
        invoke(["docker", "stop", "--time", "8", name], timeout=12)
        code = invoke(["docker", "inspect", "--format", "{{.State.ExitCode}}", name]).stdout.strip()
        assert code == "0", f"container exit {code}"
        assert not list((root / ".staging").iterdir())
        history = observations(docker_run(root, "history"))
        assert {row.get("document_id") for row in history} >= {digest(FIRST), digest(WATCHED)}
        (root / "pdfs" / "bad.pdf").write_bytes(b"not a PDF")
        assert any(row.get("outcome") == "failed" for row in observations(docker_run(root, "scan", expected=1)))
        print("PASS Docker scan, watch, concurrent status, restart history, shutdown, invalid PDF")
    finally:
        if created:
            subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=False)


def main():
    if len(sys.argv) > 2:
        raise SystemExit("usage: test-cli-docker.py [image]")
    with tempfile.TemporaryDirectory(prefix="pdf2md-cli-test-", dir="/tmp") as temp:
        base = Path(temp)
        exercise_local(base / "local")
        if os.environ.get("PDF2MD_TEST_POSTGRES_URL"):
            exercise_local(base / "postgres", pg=True)
        else:
            print("SKIP local PostgreSQL: PDF2MD_TEST_POSTGRES_URL not set")
        docker = base / "docker"
        docker.mkdir()
        exercise_docker(docker)


if __name__ == "__main__":
    main()
