#!/usr/bin/env python3
"""Check rootless Docker and effective container resource limits for CI."""
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys


class ProbeError(Exception):
    pass


class ProbeInterrupted(Exception):
    def __init__(self, code, cleanup):
        self.code = code
        self.cleanup = cleanup


def command(args, timeout):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise ProbeError("command_timeout") from None
    except OSError:
        raise ProbeError("command_unavailable") from None
    if result.returncode:
        raise ProbeError("command_failed")
    return result.stdout


def check_info(info):
    if not isinstance(info, dict):
        raise ProbeError("invalid_info")
    if "name=rootless" not in (info.get("SecurityOptions") or []):
        raise ProbeError("not_rootless")
    root = info.get("DockerRootDir")
    try:
        valid_root = isinstance(root, str) and Path(root).is_absolute() and Path(root).resolve().is_relative_to("/tmp")
    except (OSError, RuntimeError):
        valid_root = False
    if not valid_root:
        raise ProbeError("invalid_data_root")
    if str(info.get("CgroupVersion")) != "2":
        raise ProbeError("invalid_cgroup_version")
    if info.get("CgroupDriver") != "systemd":
        raise ProbeError("invalid_cgroup_driver")
    if any(info.get(key) is not True for key in ("CpuCfsQuota", "MemoryLimit", "PidsLimit")):
        raise ProbeError("missing_resource_controls")


def check_limits(output):
    try:
        cpu, memory, pids = output.strip().splitlines()
        quota, period = map(int, cpu.split())
        memory, pids = int(memory), int(pids)
        if not (quota > 0 and period > 0 and 2 * quota <= period
                and 0 < memory <= 64 * 1024 * 1024 and 0 < pids <= 64):
            raise ValueError
    except ValueError:
        raise ProbeError("limits_not_enforced") from None


def run_probe():
    image = os.environ.get("PDF2MD_POSTGRES_IMAGE", "")
    if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", image):
        return "invalid_image", "not_attempted"
    try:
        try:
            info = json.loads(command(["docker", "info", "--format", "{{json .}}"], 15))
        except (ValueError, TypeError):
            raise ProbeError("invalid_info") from None
        check_info(info)
    except ProbeError as exc:
        return str(exc), "not_attempted"

    name = "pdf2md-ci-docker-probe-" + secrets.token_hex(12)
    primary = "success"
    cleanup = "success"
    interrupted = None
    try:
        try:
            output = command([
                "docker", "run", "--name", name, "--network", "none",
                "--cpus=0.5", "--memory=64m", "--pids-limit=64", "--entrypoint", "sh",
                image, "-c", "cat /sys/fs/cgroup/cpu.max /sys/fs/cgroup/memory.max /sys/fs/cgroup/pids.max",
            ], 120)
            check_limits(output)
        except ProbeError as exc:
            primary = str(exc)
        except KeyboardInterrupt:
            interrupted = 130
        except SystemExit as exc:
            interrupted = exc.code
    finally:
        try:
            command(["docker", "rm", "--force", "--volumes", name], 30)
        except ProbeError:
            cleanup = "failure"
    if interrupted is not None:
        raise ProbeInterrupted(interrupted, cleanup)
    return primary, cleanup


def main():
    def shutdown(_signum, _frame):
        raise SystemExit(143)

    signal.signal(signal.SIGTERM, shutdown)
    exit_code = 1
    try:
        primary, cleanup = run_probe()
    except ProbeInterrupted as exc:
        primary, cleanup, exit_code = "interrupted", exc.cleanup, exc.code
    except KeyboardInterrupt:
        primary, cleanup, exit_code = "interrupted", "not_attempted", 130
    except SystemExit as exc:
        primary, cleanup, exit_code = "interrupted", "not_attempted", exc.code
    result = {"probe": primary, "cleanup": cleanup}
    diagnostics_ok = True
    try:
        directory = Path(os.environ.get("PDF2MD_CI_DIAGNOSTICS_DIR", "/tmp/pdf2md-ci/diagnostics"))
        if not directory.resolve().is_relative_to("/tmp"):
            raise ValueError
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "docker-readiness.json").write_text(json.dumps(result, indent=2) + "\n")
    except (OSError, ValueError, RuntimeError):
        print("CI Docker readiness diagnostics could not be written", file=sys.stderr)
        diagnostics_ok = False
    if primary != "success":
        print("CI Docker readiness failed: " + primary, file=sys.stderr)
    if cleanup == "failure":
        print("CI Docker probe cleanup failed or is unconfirmed", file=sys.stderr)
    if primary == "success" and cleanup == "success" and diagnostics_ok:
        print("PASS CI Docker readiness")
        return 0
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
