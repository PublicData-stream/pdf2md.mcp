#!/usr/bin/env python3
"""Validate conversion packaging in Docker and optionally a disposable minikube.

Usage: python3 scripts/test-conversion.py IMAGE [--minikube]
All documents are generated here; all disposable state is under /tmp.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

sys.dont_write_bytecode = True

from ci.minikube import install_shutdown, checked_cleanup, cleanup, start_args, verify_image


def invoke(args, *, env=None, timeout=120):
    result = subprocess.run(args, env=env, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise AssertionError(f"command failed ({args[0]}): {result.stderr[-4000:]}")
    return result.stdout


def fixture():
    content = b"BT /F1 18 Tf 40 700 Td (Conversion smoke test) Tj ET\nq 10 0 0 10 50 600 cm BI /W 1 /H 1 /CS /RGB /BPC 8 ID \xff\x00\x00 EI Q"
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
               b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
               b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
               f"<< /Length {len(content)} >>\nstream\n".encode() + content + b"\nendstream"]
    data = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for i, obj in enumerate(objects, 1):
        offsets.append(len(data))
        data.extend(f"{i} 0 obj\n".encode() + obj + b"\nendobj\n")
    xref = len(data)
    data.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        data.extend(f"{offset:010} 00000 n \n".encode())
    data.extend(f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(data)


def docker_smoke(image, base):
    root = base / "docker"
    root.mkdir()
    sample = base / "sample.pdf"
    sample.write_bytes(fixture())
    sample.chmod(0o444)
    mount = ["--mount", f"type=bind,src={root},dst=/data"]
    common = ["docker", "run", "--rm", "--network", "none", *mount]
    rootless = "name=rootless" in json.loads(invoke(["docker", "info", "--format", "{{json .SecurityOptions}}"] ))
    owner = "0:0" if rootless else f"{os.getuid()}:{os.getgid()}"
    def cli(*args):
        return invoke([*common, image, "--data-dir", "/data", "--json", *args])
    try:
        invoke([*common, "--user", "0:0", "--entrypoint", "chown", image, "10001:10001", "/data"])
        assert invoke([*common, "--entrypoint", "id", image, "-u"]).strip() == "10001"
        cli("scan")
        invoke([*common, "--mount", f"type=bind,src={sample},dst=/fixture.pdf,readonly",
                "--entrypoint", "cp", image, "/fixture.pdf", "/data/pdfs/sample.pdf"])
        acquired = json.loads(cli("scan"))
        assert acquired["document_id"] == hashlib.sha256(fixture()).hexdigest()
        attempt = json.loads(cli("conversion-history"))
        assert attempt["status"] == "succeeded", attempt
        manifest = json.loads(cli("export", attempt["id"], "--output", "/data/export"))
        assert any(a["path"].endswith(".png") for a in manifest["artifacts"])
        markdown = invoke([*common, "--entrypoint", "cat", image, "/data/export/document.md"])
        assert "Conversion smoke test" in markdown and "assets/page1_1.png" in markdown
        assert json.loads(cli("conversion-history"))["bundle_id"] == attempt["bundle_id"]
        print("PASS Docker default UID 10001, network-disabled conversion, PNG export, restart persistence")
    finally:
        cleanup("conversion bind mount", lambda: checked_cleanup([*common, "--user", "0:0", "--entrypoint", "chown", image, "-R", owner, "/data"]))


def minikube_smoke(image, base):
    env = os.environ.copy()
    env["MINIKUBE_HOME"] = str(base / "minikube")
    env["KUBECONFIG"] = str(base / "kubeconfig")
    env["TMPDIR"] = "/tmp"
    profile = "pdf2md-" + uuid.uuid4().hex[:10]
    mk = ["minikube", "--profile", profile]
    namespace = "conversion-smoke"
    def kube(*args, timeout=120):
        return invoke([*mk, "kubectl", "--", "--cache-dir", str(base / "kube-cache"), *args], env=env, timeout=timeout)
    started = False
    try:
        started = True
        invoke(start_args(mk), env=env, timeout=600)
        invoke([*mk, "image", "load", image], env=env, timeout=600)
        documents = [
            {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace}},
            {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "fixture", "namespace": namespace},
             "binaryData": {"sample.pdf": base64.b64encode(fixture()).decode()}},
        ]
        def apply(value, name):
            path = base / (name + ".json")
            path.write_text(json.dumps(value))
            kube("apply", "-f", str(path))
        for i, document in enumerate(documents):
            apply(document, f"setup-{i}")
        def job(name, script):
            spec = {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name, "namespace": namespace},
                    "spec": {"backoffLimit": 0, "template": {"spec": {"restartPolicy": "Never",
                    "initContainers": [{"name": "permissions", "image": image, "imagePullPolicy": "Never", "securityContext": {"runAsUser": 0},
                                        "command": ["sh", "-c", "mkdir -p /data && chown 10001:10001 /data"],
                                        "volumeMounts": [{"name": "data", "mountPath": "/data"}]}],
                    "containers": [{"name": "conversion", "image": image, "imagePullPolicy": "Never", "securityContext": {"runAsUser": 10001, "runAsGroup": 10001},
                                    "command": ["sh", "-ec", script], "env": [{"name": "TMPDIR", "value": "/tmp"}],
                                    "volumeMounts": [{"name": "data", "mountPath": "/data"}, {"name": "fixture", "mountPath": "/fixture", "readOnly": True}]}],
                    "volumes": [{"name": "data", "hostPath": {"path": "/tmp/pdf2md-conversion-smoke", "type": "DirectoryOrCreate"}},
                                {"name": "fixture", "configMap": {"name": "fixture"}}]}}}}
            apply(spec, name)
            kube("wait", "--namespace", namespace, "--for=condition=complete", f"job/{name}", "--timeout=180s", timeout=200)
            verify_image(kube, "job-name=" + name, "conversion", namespace=namespace)
            return kube("logs", "--namespace", namespace, f"job/{name}", "-c", "conversion")
        first = job("convert", "pdf2md-mcp --data-dir /data scan >/dev/null; cp /fixture/sample.pdf /data/pdfs/sample.pdf; pdf2md-mcp --data-dir /data --json scan >/dev/null; pdf2md-mcp --data-dir /data --json conversion-history")
        # Logs include the structured automatic-conversion summary on stderr.
        rows = [json.loads(line) for line in first.splitlines() if line.startswith("{")]
        assert rows and rows[-1]["status"] == "succeeded", first
        attempt = rows[-1]
        second = job("restart", f"pdf2md-mcp --data-dir /data --json export {attempt['id']} --output /data/export; cat /data/export/document.md; test -s /data/export/assets/page1_1.png")
        assert "Conversion smoke test" in second and "assets/page1_1.png" in second
        print("PASS minikube non-root Job, Markdown/PNG export and persistence across Jobs")
    finally:
        if started:
            cleanup("disposable conversion profile", lambda: checked_cleanup([*mk, "delete"], env=env))


def main():
    install_shutdown()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument("--minikube", action="store_true")
    args = parser.parse_args()
    # minikube's Docker driver also stores its node data in the daemon's root.
    data_root = Path(invoke(["docker", "info", "--format", "{{.DockerRootDir}}"] ).strip())
    if not data_root.is_relative_to("/tmp"):
        raise SystemExit("Use a Docker daemon whose data-root is under /tmp for disposable validation")
    with tempfile.TemporaryDirectory(prefix="pdf2md-conversion-", dir="/tmp") as temp:
        base = Path(temp)
        docker_smoke(args.image, base)
        if args.minikube:
            minikube_smoke(args.image, base)


if __name__ == "__main__":
    main()
