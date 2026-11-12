#!/usr/bin/env python3
"""Describe tested-image promotion and distinguish runtime from source inventory."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tomllib
from urllib.parse import quote

REPOSITORY = "PublicData-stream/pdf2md.mcp"
IMAGE = "ghcr.io/publicdata-stream/pdf2md.mcp"
SOURCE = "https://github.com/" + REPOSITORY
BUILD_TYPE = SOURCE + "/blob/main/docs/container-releases.md#image-promotion"
SHA256 = r"sha256:[0-9a-f]{64}"
ARCHES = ("amd64", "arm64")


def read_json(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("metadata must be a bounded regular file")
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError("metadata must be an object")
    return value


def write_json(path, value):
    encoded = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if len(encoded.encode()) > 16 * 1024 * 1024:
        raise ValueError("attestation metadata exceeds the 16 MiB limit")
    Path(path).write_text(encoded)


def validate(plan, report):
    if (plan.get("schema_version") != 1 or plan.get("repository") != REPOSITORY
            or plan.get("image") != IMAGE or report.get("image") != IMAGE
            or not re.fullmatch(r"[0-9a-f]{40}", plan.get("revision", ""))):
        raise ValueError("invalid publication metadata identity")
    source = report.get("source", {})
    if any(source.get(key) != plan.get(key) for key in ("tag", "kind", "revision", "tag_object_sha", "ci")):
        raise ValueError("publication report does not match source plan")
    if set(report.get("platforms", {})) != set(ARCHES):
        raise ValueError("publication report must contain both architectures")
    for arch in ARCHES:
        row = report["platforms"][arch]
        if (not re.fullmatch(SHA256, row.get("digest", ""))
                or not re.fullmatch(SHA256, row.get("config_digest", ""))
                or not re.fullmatch(r"[0-9a-f]{64}", row.get("archive_sha256", ""))
                or row.get("platform") != "linux/" + arch):
            raise ValueError("invalid published platform identity")
    if not re.fullmatch(SHA256, report.get("index_digest", "")):
        raise ValueError("invalid publication index digest")


def source_components(lock, arch):
    """A lockfile resolves source packages; it does not prove binary linkage."""
    result = []
    for number, package in enumerate(lock.get("package", [])):
        name, version = package["name"], package["version"]
        component = {
            "type": "library", "name": name, "version": version,
            "bom-ref": f"{arch}:cargo-lock:{number}",
            "purl": "pkg:cargo/" + quote(name, safe="") + "@" + quote(version, safe=""),
            "properties": [{"name": "pdf2md:coverage", "value": "locked-source-inventory"}],
        }
        if package.get("source"):
            component["properties"].append({"name": "pdf2md:cargo-source", "value": package["source"]})
        checksum = package.get("checksum")
        if checksum:
            if not re.fullmatch(r"[0-9a-f]{64}", checksum):
                raise ValueError("invalid Cargo source checksum")
            component["hashes"] = [{"alg": "SHA-256", "content": checksum}]
        result.append(component)
    if not result:
        raise ValueError("locked Rust source inventory is empty")
    return result


def namespace(value, arch):
    """Keep architecture-specific scanner references distinct in an index SBOM."""
    if isinstance(value, list):
        return [namespace(item, arch) for item in value]
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        if key in {"bom-ref", "ref"} and isinstance(item, str):
            result[key] = arch + ":runtime:" + item
        elif key == "dependsOn":
            result[key] = [arch + ":runtime:" + ref for ref in item]
        else:
            result[key] = namespace(item, arch)
    return result


def platform_sbom(plan, row, arch, runtime, lock, lock_digest):
    if (runtime.get("bomFormat") != "CycloneDX"
            or runtime.get("specVersion") not in {"1.6", "1.7"}
            or not isinstance(runtime.get("components"), list)
            or not runtime["components"]):
        raise ValueError("runtime scan must contain CycloneDX components")
    scanned = namespace(copy.deepcopy(runtime), arch)
    runtime_root = scanned.get("metadata", {}).get("component", {}).get("bom-ref")
    root_ref = IMAGE + "@" + row["digest"]
    inventory_ref = arch + ":cargo-lock-inventory"
    root = {
        "type": "container", "name": IMAGE, "version": plan["tag"], "bom-ref": root_ref,
        "hashes": [{"alg": "SHA-256", "content": row["digest"].split(":")[1]}],
        "properties": [{"name": "pdf2md:platform", "value": "linux/" + arch},
                       {"name": "pdf2md:source-revision", "value": plan["revision"]}],
    }
    runtime_components = scanned["components"]
    # Preserve the scanner's root when dependencies refer to it.
    if runtime_root:
        scanned_root = scanned["metadata"]["component"]
        scanned_root["components"] = runtime_components
        runtime_components = [scanned_root]
    inventory = {
        "type": "data", "name": "Cargo.lock source inventory", "bom-ref": inventory_ref,
        "description": "Resolved source inventory, including development and optional packages; not an exact linked-dependency assertion.",
        "hashes": [{"alg": "SHA-256", "content": lock_digest}],
        "components": source_components(lock, arch),
        "properties": [{"name": "pdf2md:coverage", "value": "locked-source-inventory"}],
    }
    return {
        "bomFormat": "CycloneDX", "specVersion": runtime["specVersion"], "version": 1,
        "metadata": {"component": root},
        "components": [*runtime_components, inventory],
        "dependencies": scanned.get("dependencies", []),
    }


def provenance(plan, report, target):
    dependencies = [{"uri": "git+" + SOURCE + ".git@" + plan["revision"],
                     "digest": {"gitCommit": plan["revision"]}}]
    for arch in ARCHES if target == "index" else (target,):
        row = report["platforms"][arch]
        artifact_id = plan["ci"]["artifacts"][arch]["id"]
        dependencies.append({"uri": SOURCE + "/actions/runs/" + str(plan["ci"]["run_id"])
                             + "/artifacts/" + str(artifact_id),
                             "digest": {"sha256": row["archive_sha256"]}})
    return {
        "buildDefinition": {
            "buildType": BUILD_TYPE,
            "externalParameters": {
                "operation": "promote-tested-images", "tag": plan["tag"],
                "revision": plan["revision"], "tagObjectSha": plan["tag_object_sha"],
                "target": target, "ci": plan["ci"],
                "platformConfigDigests": {arch: report["platforms"][arch]["config_digest"] for arch in ARCHES},
            },
            "internalParameters": {
                "publicationImplementationRevision": plan["trusted_revision"],
                "publicationWorkflowRef": os.environ.get("GITHUB_WORKFLOW_REF", "local"),
                "publicationWorkflowSha": os.environ.get("GITHUB_WORKFLOW_SHA", "local"),
            },
            "resolvedDependencies": dependencies,
        },
        "runDetails": {
            "builder": {"id": "https://github.com/" + os.environ.get(
                "GITHUB_WORKFLOW_REF", REPOSITORY + "/.github/workflows/publish-images.yml@local")},
            "metadata": {"invocationId": SOURCE + "/actions/runs/" + os.environ.get("GITHUB_RUN_ID", "local")
                         + "/attempts/" + os.environ.get("GITHUB_RUN_ATTEMPT", "1")},
        },
    }


def prepare(args):
    plan, report = read_json(args.plan), read_json(Path(args.output_dir) / "report.json")
    validate(plan, report)
    lock_path = Path(args.lock)
    if lock_path.is_symlink() or lock_path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("invalid source lockfile")
    lock_bytes = lock_path.read_bytes()
    lock = tomllib.loads(lock_bytes.decode())
    lock_digest = hashlib.sha256(lock_bytes).hexdigest()
    if lock_digest != plan.get("source_cargo_lock_sha256"):
        raise ValueError("source lockfile does not match the resolved release")
    output = Path(args.output_dir)
    sboms = {}
    for arch in ARCHES:
        runtime = read_json(output / ("runtime-" + arch + ".cdx.json"))
        sboms[arch] = platform_sbom(plan, report["platforms"][arch], arch, runtime, lock, lock_digest)
        write_json(output / ("sbom-" + arch + ".cdx.json"), sboms[arch])
    if sboms["amd64"]["specVersion"] != sboms["arm64"]["specVersion"]:
        raise ValueError("platform SBOM schema versions disagree")
    index = {
        "bomFormat": "CycloneDX", "specVersion": sboms["amd64"]["specVersion"], "version": 1,
        "metadata": {"component": {"type": "container", "name": IMAGE, "version": plan["tag"],
                                    "bom-ref": IMAGE + "@" + report["index_digest"]}},
        "components": [], "dependencies": [],
    }
    for arch in ARCHES:
        component = copy.deepcopy(sboms[arch]["metadata"]["component"])
        component["components"] = sboms[arch]["components"]
        index["components"].append(component)
        index["dependencies"].extend(sboms[arch]["dependencies"])
    write_json(output / "sbom-index.cdx.json", index)
    for target in (*ARCHES, "index"):
        write_json(output / ("provenance-" + target + ".json"), provenance(plan, report, target))
    write_json(output / "plan.json", plan)


def select(args):
    base = Path(args.output_dir)
    plan, report = read_json(base / "plan.json"), read_json(base / "report.json")
    validate(plan, report)
    target = args.target
    digest = report["index_digest"] if target == "index" else report["platforms"][target]["digest"]
    manifest = base / ("index.json" if target == "index" else "platform-" + target + ".json")
    if "sha256:" + hashlib.sha256(manifest.read_bytes()).hexdigest() != digest:
        raise ValueError("manifest bytes do not match attestation subject digest")
    values = {"digest": digest, "manifest": str(manifest),
              "sbom": str(base / ("sbom-" + target + ".cdx.json")),
              "predicate": str(base / ("provenance-" + target + ".json"))}
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
        for key, value in values.items():
            if "\n" in value or "\r" in value:
                raise ValueError("invalid attestation output")
            stream.write(key + "=" + value + "\n")


def record(args):
    base = Path(args.output_dir)
    report = read_json(base / "report.json")
    plan = read_json(base / "plan.json")
    validate(plan, report)
    target = args.target
    digest = report["index_digest"] if target == "index" else report["platforms"][target]["digest"]
    destination = base / "attestations" / target
    destination.mkdir(parents=True, exist_ok=True)
    result = {"target": target, "digest": digest, "verified": True}
    for kind in ("provenance", "sbom"):
        identity = os.environ[kind.upper() + "_ID"]
        url = os.environ[kind.upper() + "_URL"]
        if (not re.fullmatch(r"[1-9][0-9]*", identity)
                or url != SOURCE + "/attestations/" + identity):
            raise ValueError("invalid attestation identity")
        # Copies follow successful gh attestation verification in the workflow.
        shutil.copyfile(os.environ[kind.upper() + "_BUNDLE"], destination / (kind + ".json"))
        result[kind] = {"id": identity, "url": url}
    write_json(destination / "record.json", result)


def collect(args):
    base = Path(args.output_dir)
    report = read_json(base / "report.json")
    plan = read_json(base / "plan.json")
    validate(plan, report)
    result = {}
    for target in (*ARCHES, "index"):
        row = read_json(base / "attestations" / target / "record.json")
        digest = report["index_digest"] if target == "index" else report["platforms"][target]["digest"]
        if row.get("target") != target or row.get("digest") != digest or row.get("verified") is not True:
            raise ValueError("attestation verification record does not match publication")
        for kind in ("provenance", "sbom"):
            identity = row[kind]["id"]
            if (not re.fullmatch(r"[1-9][0-9]*", identity)
                    or row[kind]["url"] != SOURCE + "/attestations/" + identity):
                raise ValueError("invalid attestation verification reference")
        result[target] = row
    report["attestations"] = result
    write_json(base / "report.json", report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    generate = sub.add_parser("prepare")
    generate.add_argument("--plan", required=True)
    generate.add_argument("--lock", required=True)
    generate.add_argument("--output-dir", required=True)
    generate.set_defaults(callback=prepare)
    choose = sub.add_parser("select")
    choose.add_argument("--output-dir", required=True)
    choose.add_argument("--target", choices=(*ARCHES, "index"), required=True)
    choose.set_defaults(callback=select)
    save = sub.add_parser("record")
    save.add_argument("--output-dir", required=True)
    save.add_argument("--target", choices=(*ARCHES, "index"), required=True)
    save.set_defaults(callback=record)
    gather = sub.add_parser("collect")
    gather.add_argument("--output-dir", required=True)
    gather.set_defaults(callback=collect)
    args = parser.parse_args()
    try:
        args.callback(args)
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise SystemExit("Release metadata validation failed: " + str(error)) from None


if __name__ == "__main__":
    main()
