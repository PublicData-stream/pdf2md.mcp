#!/usr/bin/env python3
"""Check CI dependency pins, export image settings, and aggregate job results."""
import argparse
import json
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
SHA = r"[0-9a-f]{40}"
IMAGE = r"[^\s]+@sha256:[0-9a-f]{64}"
REQUIRED = {"source", "core", "images", "e2e", "native-e2e", "kubernetes"}
EXTENDED = {"extended-browser", "extended-oidc"}
IMAGE_ENV = {"postgres": "PDF2MD_POSTGRES_IMAGE", "authelia": "PDF2MD_AUTHELIA_IMAGE",
             "buildkit": "PDF2MD_BUILDKIT_IMAGE", "minikube": "PDF2MD_MINIKUBE_BASE_IMAGE"}


def source(root):
    errors = []
    workflows = sorted((root / ".github/workflows").glob("*.y*ml"))
    if not workflows:
        errors.append("no workflows found")
    actions = sorted((root / ".github/actions").rglob("action.y*ml"))
    for path in workflows + actions:
        for number, line in enumerate(path.read_text().splitlines(), 1):
            found = re.match(r"\s*(?:-\s*)?uses:\s*([^\s#]+)", line)
            if found and not found[1].startswith("./"):
                if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@" + SHA, found[1]):
                    errors.append(f"{path.relative_to(root)}:{number}: action must use a full commit SHA")
    dockerfiles = [root / "Dockerfile", *sorted((root / "scripts/ci").rglob("Dockerfile"))]
    for path in dockerfiles:
        for number, line in enumerate(path.read_text().splitlines(), 1):
            found = re.match(r"FROM\s+(\S+)", line, re.I)
            if found and not re.fullmatch(IMAGE, found[1]):
                errors.append(f"{path.relative_to(root)}:{number}: base image must use a digest")
            syntax = re.match(r"#\s*syntax=(\S+)", line)
            if syntax and not re.fullmatch(IMAGE, syntax[1]):
                errors.append(f"{path.relative_to(root)}:{number}: Dockerfile frontend must use a digest")
    catalog = root / "scripts/ci/compose.yml"
    if not catalog.is_file():
        errors.append("CI image catalog is missing")
    else:
        images = re.findall(r"^\s+image:\s*[\"']?([^\s\"']+)", catalog.read_text(), re.M)
        if len(images) < len(IMAGE_ENV) or any(not re.fullmatch(IMAGE, value) for value in images):
            errors.append("CI image catalog must contain digest-pinned image references")
    if errors:
        raise ValueError("\n".join(errors))
    print("PASS workflow action and container image pins")


def images(path):
    document = json.loads(Path(path).read_text())
    services = document.get("services", {})
    values = {}
    for name, variable in IMAGE_ENV.items():
        value = services.get(name, {}).get("image", "")
        if not re.fullmatch(IMAGE, value):
            raise ValueError("missing or unpinned CI image: " + name)
        values[variable] = value
    lines = "".join(key + "=" + value + "\n" for key, value in values.items())
    if os.environ.get("GITHUB_ENV"):
        with Path(os.environ["GITHUB_ENV"]).open("a") as stream:
            stream.write(lines)
    else:
        print(lines, end="")


def summary(needs, extended):
    expected = REQUIRED | (EXTENDED if extended else set())
    errors = []
    for name in sorted(expected):
        result = needs.get(name, {}).get("result", "missing")
        if result != "success":
            errors.append(name + ": " + str(result))
    for name in sorted(EXTENDED - expected):
        result = needs.get(name, {}).get("result", "missing")
        if result != "skipped":
            errors.append(name + ": expected intentional skip, got " + str(result))
    lines = ["| Job | Result |", "| --- | --- |"]
    for name in sorted(REQUIRED | EXTENDED):
        value = needs.get(name, {}).get("result", "missing")
        # These values are controlled vocabulary, never interpolate arbitrary
        # output from tested code into the GitHub summary.
        value = value if value in {"success", "failure", "skipped", "cancelled", "missing"} else "invalid"
        lines.append("| " + name + " | " + value + " |")
    report = "\n".join(lines) + "\n"
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as stream:
            stream.write(report)
    print(report, end="")
    if errors:
        raise ValueError("required CI results were not successful: " + ", ".join(errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("source")
    check.add_argument("--root", type=Path, default=ROOT)
    catalog = commands.add_parser("images")
    catalog.add_argument("--compose-json", required=True)
    aggregate = commands.add_parser("summary")
    aggregate.add_argument("--needs-json", required=True)
    aggregate.add_argument("--extended", choices=("true", "false"), required=True)
    args = parser.parse_args()
    try:
        if args.command == "source":
            source(args.root)
        elif args.command == "images":
            images(args.compose_json)
        else:
            summary(json.loads(Path(args.needs_json).read_text()), args.extended == "true")
    except (ValueError, KeyError, OSError) as error:
        raise SystemExit("CI check failed: " + str(error)) from None


if __name__ == "__main__":
    main()
