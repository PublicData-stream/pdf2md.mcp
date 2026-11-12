#!/usr/bin/env python3
"""Bind reusable CI executables and Docker archives to one commit and platform."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile

TARGET = Path("/tmp/rust/target")
MACHINES = {"amd64": 62, "arm64": 183}


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def identity(commit, arch):
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or arch not in MACHINES:
        raise ValueError("invalid artifact identity")
    return {"commit": commit, "arch": arch, "os": "ubuntu-24.04", "profile": "debug"}


def elf_arch(path, arch):
    with Path(path).open("rb") as stream:
        header = stream.read(20)
    if (len(header) != 20 or header[:6] != b"\x7fELF\x02\x01"
            or int.from_bytes(header[18:20], "little") != MACHINES[arch]):
        raise ValueError("artifact executable architecture mismatch")


def native_files(cargo_json, target):
    selected = {}
    for line in Path(cargo_json).read_text().splitlines():
        row = json.loads(line)
        if row.get("reason") != "compiler-artifact" or not row.get("executable"):
            continue
        item = row.get("target", {})
        if item.get("name") == "pdf2md_mcp" and "lib" in item.get("kind", []):
            selected["browser"] = Path(row["executable"])
        if item.get("name") == "live_casdoor" and "test" in item.get("kind", []):
            selected["casdoor"] = Path(row["executable"])
    selected.update({name: target / "debug" / name for name in (
        "pdf2md-mcp", "pdf2md-convert-worker", "pdf2md-obscura-worker")})
    if set(selected) != {"browser", "casdoor", "pdf2md-mcp", "pdf2md-convert-worker", "pdf2md-obscura-worker"}:
        raise ValueError("Cargo output is missing a required test executable")
    return selected


def pack_native(args):
    metadata = identity(args.commit, args.arch)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    target = Path(args.target_dir).resolve()
    files = native_files(args.cargo_json, target)
    metadata["files"] = []
    with tarfile.open(output / "native.tar.gz", "w:gz") as archive:
        for role, path in files.items():
            if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
                raise ValueError("required native executable is missing or not executable")
            elf_arch(path, args.arch)
            relative = path.resolve().relative_to(target / "debug").as_posix()
            metadata["files"].append({"role": role, "path": relative,
                                      "sha256": digest(path), "mode": 0o755})
            archive.add(path, arcname=relative, recursive=False)
    metadata["archive_sha256"] = digest(output / "native.tar.gz")
    (output / "manifest.json").write_text(json.dumps(metadata, indent=2) + "\n")


def read_manifest(args, kind):
    base = Path(args.input)
    metadata = json.loads((base / "manifest.json").read_text())
    expected = identity(args.commit, args.arch)
    for key in ("commit", "arch", "os"):
        if metadata.get(key) != expected[key]:
            raise ValueError("artifact identity mismatch")
    if kind == "native" and metadata.get("profile") != "debug":
        raise ValueError("native artifact profile mismatch")
    name = "native.tar.gz" if kind == "native" else "image.tar"
    if metadata.get("archive_sha256") != digest(base / name):
        raise ValueError("artifact archive checksum mismatch")
    return base, metadata


def emit_env(values):
    destination = os.environ.get("GITHUB_ENV")
    lines = []
    for key, value in values.items():
        if "\n" in str(value) or "\r" in str(value):
            raise ValueError("invalid artifact environment value")
        lines.append(key + "=" + str(value) + "\n")
    if destination:
        with Path(destination).open("a") as stream:
            stream.writelines(lines)
    else:
        print("".join(lines), end="")


def safe_destination(target, relative):
    destination = target / relative
    # Refuse pre-existing directory links as well as a linked final file. This
    # keeps a reused /tmp target from redirecting extraction outside its root.
    if target.is_symlink():
        raise ValueError("native artifact destination contains a symlink")
    current = target
    for part in Path(relative).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("native artifact destination contains a symlink")
    return destination


def restore_native(args):
    base, metadata = read_manifest(args, "native")
    machine = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if machine != args.arch:
        raise ValueError("native artifact does not match this runner")
    files = metadata.get("files", [])
    expected_roles = {"browser", "casdoor", "pdf2md-mcp", "pdf2md-convert-worker", "pdf2md-obscura-worker"}
    if len(files) != 5 or {row["role"] for row in files} != expected_roles:
        raise ValueError("native artifact role manifest is incomplete")
    target = Path(args.target_dir).resolve() / "debug"
    # Validate the complete archive before writing any executable. Never extract
    # links, paths supplied by tar headers, or files absent from the manifest.
    with tarfile.open(base / "native.tar.gz", "r:gz") as archive:
        members = archive.getmembers()
        paths = [row["path"] for row in files]
        if len(set(paths)) != len(paths) or {m.name for m in members} != set(paths) or len(members) != len(paths):
            raise ValueError("native artifact archive membership mismatch")
        for member in members:
            relative = Path(member.name)
            if not member.isfile() or relative.is_absolute() or ".." in relative.parts:
                raise ValueError("unsafe native artifact member")
            safe_destination(target, member.name)
            expected = next(row for row in files if row["path"] == member.name)
            with archive.extractfile(member) as stream:
                value = hashlib.sha256()
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    value.update(block)
            if value.hexdigest() != expected["sha256"] or expected.get("mode") != 0o755:
                raise ValueError("native executable checksum or mode mismatch")
        for row in files:
            destination = safe_destination(target, row["path"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.is_symlink():
                raise ValueError("native artifact destination is a symlink")
            with archive.extractfile(row["path"]) as source, destination.open("wb") as output:
                shutil.copyfileobj(source, output)
            destination.chmod(0o755)
            elf_arch(destination, args.arch)
    selected = {row["role"]: target / row["path"] for row in files}
    if os.environ.get("GITHUB_PATH"):
        with Path(os.environ["GITHUB_PATH"]).open("a") as stream:
            stream.write(str(target) + "\n")
    emit_env({"PDF2MD_BROWSER_TEST_EXECUTABLE": selected["browser"],
              "PDF2MD_LIVE_CASDOOR_TEST_EXECUTABLE": selected["casdoor"],
              "PDF2MD_TEST_CLI": selected["pdf2md-mcp"],
              "PDF2MD_TEST_WORKER": selected["pdf2md-obscura-worker"]})


def archive_image(archive_path, image):
    """Read an image's configuration bytes, independent of Docker's .Id shape."""
    with tarfile.open(archive_path, "r:*") as archive:
        def read_blob(name):
            path = Path(name)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("unsafe image archive member")
            member = archive.getmember(name)
            if not member.isfile() or member.size > 16 * 1024 * 1024:
                raise ValueError("invalid image metadata member")
            with archive.extractfile(member) as stream:
                return stream.read()

        def config_identity(blob):
            config = json.loads(blob)
            return {"config_digest": "sha256:" + hashlib.sha256(blob).hexdigest(),
                    "platform": config["os"] + "/" + config["architecture"]}

        names = set(archive.getnames())
        candidates = []
        if "manifest.json" in names:
            # Both classic Docker and the containerd image store export this
            # manifest. Config may be '<digest>.json' or 'blobs/sha256/<digest>'.
            manifests = json.loads(read_blob("manifest.json"))
            tagged = [row for row in manifests if image in row.get("RepoTags", [])]
            if not tagged:
                raise ValueError("image archive does not contain the expected tag")
            for row in tagged:
                blob = read_blob(row["Config"])
                value = config_identity(blob)
                name = row["Config"]
                expected = re.fullmatch(r"(?:blobs/sha256/)?([0-9a-f]{64})(?:\.json)?", name)
                if expected and value["config_digest"] != "sha256:" + expected[1]:
                    raise ValueError("image config blob digest mismatch")
                candidates.append(value)
        elif "index.json" in names:
            # OCI-only exports name a manifest or nested index through immutable
            # descriptors. Attestations have unknown platform and are excluded.
            def descriptor_blob(descriptor):
                reference = descriptor.get("digest", "")
                if not re.fullmatch(r"sha256:[0-9a-f]{64}", reference):
                    raise ValueError("unsupported OCI image descriptor")
                blob = read_blob("blobs/sha256/" + reference.split(":", 1)[1])
                if "sha256:" + hashlib.sha256(blob).hexdigest() != reference:
                    raise ValueError("OCI image descriptor checksum mismatch")
                return blob

            def visit(descriptor, depth=0):
                if depth > 4:
                    raise ValueError("OCI image index nesting is too deep")
                document = json.loads(descriptor_blob(descriptor))
                if "manifests" in document:
                    for child in document["manifests"]:
                        visit(child, depth + 1)
                elif "config" in document:
                    candidates.append(config_identity(descriptor_blob(document["config"])))
                else:
                    raise ValueError("invalid OCI image manifest")

            for descriptor in json.loads(read_blob("index.json")).get("manifests", []):
                visit(descriptor)
        else:
            raise ValueError("image archive has no supported manifest")
        supported = [value for value in candidates if value["platform"] in {"linux/amd64", "linux/arm64"}]
        if len(supported) != 1:
            raise ValueError("image archive must contain exactly one runnable platform image")
        return supported[0]


def inspect_image(image, archive=None):
    result = subprocess.run(["docker", "image", "inspect", image], check=True,
                            capture_output=True, text=True)
    row = json.loads(result.stdout)[0]
    platform = row["Os"] + "/" + row["Architecture"]
    # Modern Docker may expose an OCI index as .Id. Kubernetes reports the
    # platform configuration digest, so derive it from an actual saved config.
    if archive is None:
        with tempfile.TemporaryDirectory(prefix="pdf2md-ci-image-", dir="/tmp") as temporary:
            archive = Path(temporary) / "image.tar"
            subprocess.run(["docker", "image", "save", "--output", str(archive), image],
                           check=True, stdout=subprocess.DEVNULL, timeout=600)
            observed = archive_image(archive, image)
    else:
        observed = archive_image(archive, image)
    if observed["platform"] != platform:
        raise ValueError("image archive and inspected platform disagree")
    return observed


def pack_image(args):
    metadata = identity(args.commit, args.arch)
    metadata.update(inspect_image(args.image, args.archive))
    if metadata["platform"] != "linux/" + args.arch:
        raise ValueError("built image architecture mismatch")
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    archive = Path(args.archive)
    if archive.resolve() != (output / "image.tar").resolve():
        shutil.copyfile(archive, output / "image.tar")
    metadata.update({"image": args.image, "archive_sha256": digest(output / "image.tar")})
    (output / "manifest.json").write_text(json.dumps(metadata, indent=2) + "\n")


def load_image(args):
    base, metadata = read_manifest(args, "image")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", metadata.get("config_digest", "")):
        raise ValueError("invalid image configuration digest")
    if metadata.get("platform") != "linux/" + args.arch:
        raise ValueError("image platform mismatch")
    image = metadata.get("image", "")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]+", image):
        raise ValueError("invalid image tag")
    archived = archive_image(base / "image.tar", image)
    if archived != {key: metadata[key] for key in ("config_digest", "platform")}:
        raise ValueError("archived image identity mismatch")
    subprocess.run(["docker", "load", "--input", str(base / "image.tar")],
                   check=True, stdout=subprocess.DEVNULL)
    observed = inspect_image(image)
    if observed != {key: metadata[key] for key in ("config_digest", "platform")}:
        raise ValueError("loaded image identity mismatch")
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", args.env_name):
        raise ValueError("invalid image environment name")
    values = {args.env_name: image}
    if args.env_name == "CI_IMAGE":
        values["PDF2MD_EXPECTED_IMAGE_CONFIG_DIGEST"] = metadata["config_digest"]
    emit_env(values)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, callback in (("pack-native", pack_native), ("restore-native", restore_native),
                           ("pack-image", pack_image), ("load-image", load_image)):
        command = commands.add_parser(name)
        command.add_argument("--commit", required=True)
        command.add_argument("--arch", choices=MACHINES, required=True)
        if name.startswith("pack-"):
            command.add_argument("--output", required=True)
        else:
            command.add_argument("--input", required=True)
        if name.endswith("native"):
            command.add_argument("--target-dir", default=str(TARGET))
        if name == "pack-native":
            command.add_argument("--cargo-json", required=True)
        if name == "load-image":
            command.add_argument("--env-name", default="CI_IMAGE")
        if name == "pack-image":
            command.add_argument("--image", required=True)
            command.add_argument("--archive", required=True)
        command.set_defaults(callback=callback)
    args = parser.parse_args()
    try:
        args.callback(args)
    except (ValueError, KeyError, OSError, tarfile.TarError, subprocess.SubprocessError) as error:
        raise SystemExit("CI artifact validation failed: " + str(error)) from None


if __name__ == "__main__":
    main()
