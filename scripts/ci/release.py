#!/usr/bin/env python3
"""Resolve a release tag to retained images from successful canonical CI.

Only GitHub reads and local Git fetches occur here. No release source code is
executed: Cargo manifests and the lockfile are read as data from the tag commit.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib
from urllib.parse import quote, urlencode

REPOSITORY = "PublicData-stream/pdf2md.mcp"
SOURCE = "https://github.com/" + REPOSITORY
IMAGE = "ghcr.io/publicdata-stream/pdf2md.mcp"
WORKFLOW = ".github/workflows/check.yml"
SHA = re.compile(r"[0-9a-f]{40}")
NUMBER = r"(?:0|[1-9][0-9]*)"
TAG = re.compile(rf"({NUMBER}\.({NUMBER})\.({NUMBER}))(?:-(beta)\.([1-9][0-9]*)|-(build)\.([0-9a-f]{{8}}))?")
MAX_JSON = 16 * 1024 * 1024
MAX_PAGES = 100


def positive(value):
    return type(value) is int and value > 0


def parse_tag(tag):
    if not isinstance(tag, str) or len(tag) > 128:
        raise ValueError("invalid release tag")
    match = TAG.fullmatch(tag)
    if not match:
        raise ValueError("tag must be X.Y.Z, X.Y.Z-beta.N, or X.Y.Z-build.<sha8> without a v prefix")
    return {"tag": tag, "base": match[1],
            "kind": "beta" if match[4] else "build" if match[6] else "stable",
            "commit_prefix": match[7]}


def run(command, limit=MAX_JSON):
    # Capture into disposable files, rather than retaining arbitrary command
    # output or exposing credential-bearing diagnostics to logs.
    with tempfile.TemporaryFile(dir="/tmp") as output, tempfile.TemporaryFile(dir="/tmp") as error:
        result = subprocess.run(command, stdout=output, stderr=error, timeout=120)
        if output.tell() > limit or error.tell() > limit:
            raise ValueError("command response exceeds the validation bound")
        output.seek(0)
        error.seek(0)
        return result.returncode, output.read(), error.read()


def git(*arguments):
    code, output, _ = run(["git", *arguments])
    if code:
        raise ValueError("Git source validation failed")
    text = output.decode()
    return text if arguments[0] == "show" else text.strip()


def api(endpoint, optional=False):
    code, response, _ = run(["gh", "api", "--method", "GET", "--include", endpoint])
    separator = b"\r\n\r\n" if b"\r\n\r\n" in response else b"\n\n"
    headers, found, body = response.partition(separator)
    status = re.match(rb"HTTP/\S+\s+(\d{3})\b", headers)
    if not found or status is None:
        raise ValueError("GitHub API did not return an HTTP response")
    status = int(status[1])
    if optional and status == 404:
        return None
    if code or status != 200:
        raise ValueError("GitHub API read failed with HTTP status " + str(status))
    return json.loads(body)


def pages(endpoint, key):
    result = []
    for page in range(1, MAX_PAGES + 1):
        separator = "&" if "?" in endpoint else "?"
        document = api(endpoint + separator + urlencode({"per_page": 100, "page": page}))
        rows = document.get(key)
        if not isinstance(rows, list) or len(rows) > 100:
            raise ValueError("invalid GitHub collection response")
        result.extend(rows)
        if len(rows) < 100:
            return result
    raise ValueError("GitHub collection exceeds the pagination bound")


def validate_event(tag, kind, event_name, event, environment):
    if environment.get("GITHUB_REPOSITORY") != REPOSITORY or event.get("repository", {}).get("full_name") != REPOSITORY:
        raise ValueError("publication is restricted to the canonical repository")
    reference = environment.get("GITHUB_REF")
    if event_name == "workflow_dispatch":
        if reference != "refs/heads/main":
            raise ValueError("manual publication must run from main")
    elif event_name == "push":
        if (kind != "build" or reference != "refs/tags/" + tag
                or event.get("ref") != reference or event.get("deleted") is not False
                or event.get("created") is not True or event.get("forced") is not False):
            raise ValueError("only creation of a build-candidate tag may publish on push")
    elif event_name == "release":
        release = event.get("release", {})
        if (kind == "build" or reference != "refs/tags/" + tag
                or event.get("action") != "published" or release.get("tag_name") != tag
                or release.get("draft") is not False or not release.get("published_at")
                or release.get("prerelease") is not (kind == "beta")
                or not positive(release.get("id"))):
            raise ValueError("published Release does not match the release tag class")
    else:
        raise ValueError("unsupported publication event")


def release_state(tag, kind, event_name, event):
    release = api(f"repos/{REPOSITORY}/releases/tags/{quote(tag, safe='')}", optional=True)
    if kind == "build":
        if release is not None:
            raise ValueError("build candidates must not have a GitHub Release")
        return None
    if (not isinstance(release, dict) or release.get("tag_name") != tag
            or not positive(release.get("id")) or release.get("draft") is not False
            or not release.get("published_at") or release.get("prerelease") is not (kind == "beta")):
        raise ValueError("an eligible published stable/beta GitHub Release is required")
    if event_name == "release" and release["id"] != event["release"]["id"]:
        raise ValueError("published Release identity changed")
    return {key: release[key] for key in ("id", "tag_name", "draft", "prerelease", "published_at")}


def source_identity(info):
    remote = api(f"repos/{REPOSITORY}/git/ref/tags/{quote(info['tag'], safe='')}")
    tag_object = remote.get("object", {})
    if tag_object.get("type") != "tag" or not SHA.fullmatch(tag_object.get("sha", "")):
        raise ValueError("release tag must be annotated")
    tag_sha = tag_object["sha"]
    annotation = api(f"repos/{REPOSITORY}/git/tags/{tag_sha}")
    target = annotation.get("object", {})
    if (annotation.get("sha") != tag_sha or annotation.get("tag") != info["tag"]
            or target.get("type") != "commit" or not SHA.fullmatch(target.get("sha", ""))):
        raise ValueError("annotated tag must refer directly to a commit")
    revision = target["sha"]
    git("fetch", "--no-tags", "origin", "+refs/heads/main:refs/remotes/origin/main",
        f"+refs/tags/{info['tag']}:refs/pdf2md-release/{info['tag']}")
    reference = "refs/pdf2md-release/" + info["tag"]
    if git("rev-parse", reference) != tag_sha or git("rev-parse", reference + "^{commit}") != revision:
        raise ValueError("release tag changed while fetching source")
    trusted_revision = git("rev-parse", "HEAD")
    if not SHA.fullmatch(trusted_revision):
        raise ValueError("invalid trusted checkout revision")
    git("merge-base", "--is-ancestor", trusted_revision, "refs/remotes/origin/main")
    git("merge-base", "--is-ancestor", revision, "refs/remotes/origin/main")
    if info["kind"] == "build" and not revision.startswith(info["commit_prefix"]):
        raise ValueError("build tag suffix must match the first eight source commit characters")
    versions = {}
    expected = info["tag"] if info["kind"] != "build" else info["base"]
    for path, name in (("Cargo.toml", "pdf2md-mcp"),
                       ("crates/obscura-worker/Cargo.toml", "pdf2md-obscura-worker")):
        package = tomllib.loads(git("show", revision + ":" + path)).get("package", {})
        if package.get("name") != name or package.get("version") != expected:
            raise ValueError("release tag does not match both source Cargo package versions")
        versions[name] = package["version"]
    return revision, tag_sha, trusted_revision, versions


def ci_identity(revision):
    endpoint = (f"repos/{REPOSITORY}/actions/workflows/check.yml/runs?"
                + urlencode({"branch": "main", "event": "push", "head_sha": revision}))
    rows = pages(endpoint, "workflow_runs")
    candidates = [row for row in rows if row.get("path") == WORKFLOW
                  and row.get("event") == "push" and row.get("head_branch") == "main"
                  and row.get("head_sha") == revision
                  and row.get("repository", {}).get("full_name") == REPOSITORY
                  and row.get("head_repository", {}).get("full_name") == REPOSITORY]
    if not candidates or any(not positive(row.get("id")) for row in candidates):
        raise ValueError("no canonical main push CI run exists for the exact release commit")
    selected = max(candidates, key=lambda row: row["id"])
    run_id = selected["id"]
    current = api(f"repos/{REPOSITORY}/actions/runs/{run_id}")
    keys = ("id", "path", "event", "head_branch", "head_sha", "run_attempt", "workflow_id")
    if (any(current.get(key) != selected.get(key) for key in keys)
            or current.get("repository", {}).get("full_name") != REPOSITORY
            or current.get("head_repository", {}).get("full_name") != REPOSITORY
            or current.get("status") != "completed" or current.get("conclusion") != "success"
            or not positive(current.get("run_attempt")) or not positive(current.get("workflow_id"))):
        raise ValueError("newest exact-commit canonical CI run must be completed successfully")
    attempt = current["run_attempt"]
    jobs = pages(f"repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}/jobs", "jobs")
    summaries = [job for job in jobs if job.get("name") == "CI summary"]
    if (len(summaries) != 1 or summaries[0].get("head_sha") != revision
            or summaries[0].get("status") != "completed" or summaries[0].get("conclusion") != "success"):
        raise ValueError("selected CI attempt requires exactly one successful CI summary")
    # Partial reruns deliberately reuse artifacts from successful image jobs in
    # this same run; all-attempt job results let us bind their creation windows.
    all_jobs = pages(f"repos/{REPOSITORY}/actions/runs/{run_id}/jobs?filter=all", "jobs")
    artifacts = pages(f"repos/{REPOSITORY}/actions/runs/{run_id}/artifacts", "artifacts")
    selected_artifacts = {}
    for arch in ("amd64", "arm64"):
        matches = [row for row in artifacts if row.get("name") == "image-" + arch]
        if len(matches) != 1:
            raise ValueError("required runtime artifact is missing or ambiguous; rerun exact-commit CI")
        artifact = matches[0]
        if artifact.get("expired") is not False:
            raise ValueError(f"runtime artifact image-{arch} is expired or expiry is unverifiable")
        origin = artifact.get("workflow_run", {})
        if (not positive(artifact.get("id")) or not isinstance(origin, dict)
                or origin.get("id") != run_id or origin.get("head_sha") != revision
                or origin.get("head_branch") != "main"):
            raise ValueError(f"runtime artifact image-{arch} has invalid exact-source origin metadata")
        producer = [job for job in all_jobs if job.get("name") == f"Build container images ({arch})"
                    and job.get("head_sha") == revision and job.get("status") == "completed"
                    and job.get("conclusion") == "success" and job.get("started_at")
                    and job.get("completed_at") and job["started_at"] <= artifact.get("created_at", "") <= job["completed_at"]]
        if not producer:
            raise ValueError(f"runtime artifact image-{arch} has no successful exact-source image job")
        # Partial reruns can carry the same execution forward with new job IDs
        # and attempt numbers. Correlate those rows by runner and execution
        # window; distinct or unverifiable executions remain ambiguous.
        if len(producer) > 1:
            if (any(not positive(job.get("runner_id")) for job in producer)
                    or len({(job["runner_id"], job["started_at"], job["completed_at"])
                            for job in producer}) != 1):
                raise ValueError(f"runtime artifact image-{arch} has ambiguous image producer executions")
        selected_artifacts[arch] = {"id": artifact["id"], "name": artifact["name"]}
    final = api(f"repos/{REPOSITORY}/actions/runs/{run_id}")
    if (any(final.get(key) != current.get(key) for key in keys)
            or final.get("status") != "completed" or final.get("conclusion") != "success"):
        raise ValueError("CI run changed while validating release evidence")
    return {"run_id": run_id, "run_attempt": attempt, "workflow_path": WORKFLOW,
            "artifacts": selected_artifacts}


def resolve(environment=None):
    environment = os.environ if environment is None else environment
    info = parse_tag(environment.get("RELEASE_TAG"))
    event_path = Path(environment["GITHUB_EVENT_PATH"])
    if event_path.stat().st_size > MAX_JSON:
        raise ValueError("GitHub event exceeds the validation bound")
    event = json.loads(event_path.read_text())
    event_name = environment.get("GITHUB_EVENT_NAME")
    validate_event(info["tag"], info["kind"], event_name, event, environment)
    state = release_state(info["tag"], info["kind"], event_name, event)
    revision, tag_sha, trusted_revision, versions = source_identity(info)
    if event_name != "workflow_dispatch" and environment.get("GITHUB_SHA") != revision:
        raise ValueError("event source commit does not match the annotated release tag")
    ci = ci_identity(revision)
    lockfile = git("show", revision + ":Cargo.lock")
    return {"schema_version": 1, "repository": REPOSITORY, "source_url": SOURCE, "image": IMAGE,
            "tag": info["tag"], "version": info["tag"], "kind": info["kind"], "revision": revision,
            "tag_object_sha": tag_sha, "trusted_revision": trusted_revision, "ci": ci,
            "package_versions": versions, "release": state,
            "source_cargo_lock_sha256": hashlib.sha256(lockfile.encode()).hexdigest()}, lockfile


def write_outputs(plan):
    destination = os.environ.get("GITHUB_OUTPUT")
    if not destination:
        return
    outputs = {"revision": plan["revision"], "tag_object_sha": plan["tag_object_sha"],
               "run_id": plan["ci"]["run_id"], "run_attempt": plan["ci"]["run_attempt"],
               "amd64_artifact_id": plan["ci"]["artifacts"]["amd64"]["id"],
               "arm64_artifact_id": plan["ci"]["artifacts"]["arm64"]["id"]}
    with Path(destination).open("a") as stream:
        stream.writelines(f"{key}={value}\n" for key, value in outputs.items())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("resolve")
    create.add_argument("--output-dir", required=True, type=Path)
    check = commands.add_parser("recheck")
    check.add_argument("--plan", required=True, type=Path)
    args = parser.parse_args()
    try:
        plan, lockfile = resolve()
        if args.command == "recheck":
            original = json.loads(args.plan.read_text())
            if original != plan or (args.plan.parent / "source-Cargo.lock").read_text() != lockfile:
                raise ValueError("release source, CI attempt, artifacts, or Release metadata changed; resolve again")
            print("PASS unchanged release source and CI evidence")
        else:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            (args.output_dir / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
            (args.output_dir / "source-Cargo.lock").write_text(lockfile)
            write_outputs(plan)
            print("PASS release source and retained CI images")
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit("Release validation failed: " + str(error)) from None


if __name__ == "__main__":
    main()
