#!/usr/bin/env python3
"""Exercise HTTP conversion and persistence in Docker and optionally minikube.

Usage: python3 scripts/test-http.py IMAGE [--minikube]
Requires a rootless Docker daemon with data-root under /tmp. The optional
minikube uses a unique profile and isolated configuration and cache under /tmp.
"""
import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
import zipfile

sys.dont_write_bytecode = True

from ci.minikube import install_shutdown, checked_cleanup, cleanup, start_args, verify_image


def invoke(args, *, env=None, timeout=120):
    result = subprocess.run(args, env=env, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed: {result.stderr[-3000:]}")
    return result.stdout


def fixture():
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("conversion_fixture", Path(__file__).with_name("test-conversion.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.fixture()


def request(base, path, data=None, content_type=None):
    headers = {"Content-Type": content_type} if content_type else {}
    with urllib.request.urlopen(urllib.request.Request(base + path, data=data, headers=headers), timeout=20) as response:
        return response.read()


def ready(base):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            request(base, "/readyz")
            return
        except (OSError, urllib.error.URLError):
            time.sleep(0.5)
    raise RuntimeError("HTTP service did not become ready")


def exercise(base):
    ready(base)
    uploaded = json.loads(request(base, "/v1/documents", fixture(), "application/pdf"))
    document = uploaded["observation"]["document_id"]
    job = uploaded["conversion_job"]
    assert job, uploaded
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        job = json.loads(request(base, "/v1/jobs/" + job["id"]))
        if job["status"] == "succeeded":
            break
        if job["status"] in ("failed", "cancelled", "interrupted"):
            raise AssertionError(job)
        time.sleep(0.5)
    else:
        raise RuntimeError("conversion did not finish")
    conversion = job["conversion_id"]
    prefix = "/v1/conversions/" + conversion
    manifest = json.loads(request(base, prefix + "/manifest"))
    markdown = request(base, prefix + "/markdown").decode()
    assert "Conversion smoke test" in markdown
    assets = [a["path"] for a in manifest["artifacts"] if a["path"].startswith("assets/")]
    assert assets, manifest
    assert request(base, prefix + "/assets/" + assets[0].removeprefix("assets/"))
    with zipfile.ZipFile(io.BytesIO(request(base, prefix + "/bundle.zip"))) as bundle:
        assert "document.md" in bundle.namelist() and assets[0] in bundle.namelist()
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("mcp_smoke", Path(__file__).with_name("mcp-smoke.py"))
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
    smoke.exercise(base, conversion, markdown)
    return document, conversion


def verify_restart(base, document, conversion):
    ready(base)
    assert "Conversion smoke test" in request(base, "/v1/conversions/" + conversion + "/markdown").decode()
    assert document in request(base, "/v1/history").decode()
    spec = importlib.util.spec_from_file_location("mcp_smoke", Path(__file__).with_name("mcp-smoke.py"))
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
    smoke.call(base, "read", {"conversion_id": conversion})


def docker_smoke(image, base):
    root = base / "data"
    root.mkdir()
    config = base / "config.toml"
    config.write_text('[auth]\nmode = "none_rw"\n[mcp]\nenabled = true\n')
    config.chmod(0o444)
    name = "pdf2md-http-" + uuid.uuid4().hex[:10]
    mount = ["--mount", f"type=bind,src={root},dst=/data"]
    try:
        invoke(["docker", "run", "--rm", "--network", "none", *mount, "--user", "0:0", "--entrypoint", "chown", image, "10001:10001", "/data"])
        invoke(["docker", "run", "-d", "--name", name, "-p", "127.0.0.1::8080", *mount,
                "--mount", f"type=bind,src={config},dst=/etc/pdf2md/config.toml,readonly", image,
                "--data-dir", "/data", "--config", "/etc/pdf2md/config.toml", "serve", "--listen", "0.0.0.0:8080"])
        port = invoke(["docker", "port", name, "8080/tcp"]).strip().rsplit(":", 1)[1]
        url = "http://127.0.0.1:" + port
        document, conversion = exercise(url)
        invoke(["docker", "restart", name])
        # Docker may allocate a different host port for an ephemeral publication.
        port = invoke(["docker", "port", name, "8080/tcp"]).strip().rsplit(":", 1)[1]
        url = "http://127.0.0.1:" + port
        verify_restart(url, document, conversion)
        print("PASS Docker HTTP upload, conversion, bundle and restart persistence")
    finally:
        cleanup("disposable HTTP container",
                lambda: checked_cleanup(["docker", "rm", "-f", name]),
                lambda: checked_cleanup(["docker", "run", "--rm", "--network", "none", *mount, "--user", "0:0", "--entrypoint", "chown", image, "-R", "0:0", "/data"]))


def minikube_smoke(image, base):
    env = os.environ.copy()
    env.update(MINIKUBE_HOME=str(base / "minikube"), KUBECONFIG=str(base / "kubeconfig"), TMPDIR="/tmp")
    profile = "pdf2md-http-" + uuid.uuid4().hex[:10]
    mk = ["minikube", "--profile", profile]
    def kube(*args, timeout=120):
        return invoke([*mk, "kubectl", "--", "--cache-dir", str(base / "kube-cache"), *args], env=env, timeout=timeout)
    forward = None
    try:
        print("Starting disposable Minikube HTTP profile", flush=True)
        invoke(start_args(mk), env=env, timeout=600)
        print("Loading HTTP image into Minikube", flush=True)
        invoke([*mk, "image", "load", image], env=env, timeout=600)
        config = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "config"}, "data": {"config.toml": '[auth]\nmode = "none_rw"\n[mcp]\nenabled = true\n'}}
        pvc = {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "data"}, "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Gi"}}}}
        deployment = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "http"}, "spec": {"replicas": 1, "strategy": {"type": "Recreate"}, "selector": {"matchLabels": {"app": "http"}}, "template": {"metadata": {"labels": {"app": "http"}}, "spec": {"securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001, "fsGroup": 10001}, "containers": [{"name": "http", "image": image, "imagePullPolicy": "Never", "args": ["--data-dir", "/data", "--config", "/etc/pdf2md/config.toml", "serve", "--listen", "0.0.0.0:8080"], "ports": [{"containerPort": 8080}], "readinessProbe": {"httpGet": {"path": "/readyz", "port": 8080}}, "volumeMounts": [{"name": "data", "mountPath": "/data"}, {"name": "config", "mountPath": "/etc/pdf2md/config.toml", "subPath": "config.toml", "readOnly": True}]}], "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "data"}}, {"name": "config", "configMap": {"name": "config"}}]}}}}
        path = base / "resources.json"
        path.write_text(json.dumps({"apiVersion": "v1", "kind": "List", "items": [config, pvc, deployment]}))
        kube("apply", "-f", str(path))
        print("Waiting for Minikube HTTP deployment", flush=True)
        kube("rollout", "status", "deployment/http", "--timeout=180s", timeout=200)
        verify_image(kube, "app=http", "http")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        def start_forward():
            return subprocess.Popen([*mk, "kubectl", "--", "--cache-dir", str(base / "kube-cache"), "port-forward", "deployment/http", f"{port}:8080"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        forward = start_forward()
        url = f"http://127.0.0.1:{port}"
        document, conversion = exercise(url)
        forward.terminate()
        forward.wait(timeout=10)
        forward = None
        kube("rollout", "restart", "deployment/http")
        kube("rollout", "status", "deployment/http", "--timeout=180s", timeout=200)
        verify_image(kube, "app=http", "http")
        forward = start_forward()
        verify_restart(url, document, conversion)
        print("PASS minikube HTTP upload, conversion, bundle and rollout persistence")
    finally:
        def stop_forward():
            if forward:
                forward.terminate()
                try:
                    forward.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    forward.kill()
                    forward.wait(timeout=10)
        cleanup("disposable HTTP profile", stop_forward,
                lambda: checked_cleanup([*mk, "delete"], env=env))


def main():
    install_shutdown()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument("--minikube", action="store_true")
    args = parser.parse_args()
    root = Path(invoke(["docker", "info", "--format", "{{.DockerRootDir}}"] ).strip()).resolve()
    options = json.loads(invoke(["docker", "info", "--format", "{{json .SecurityOptions}}"] ))
    if not root.is_relative_to("/tmp") or "name=rootless" not in options:
        raise SystemExit("Use a rootless Docker daemon with data-root under /tmp")
    with tempfile.TemporaryDirectory(prefix="pdf2md-http-", dir="/tmp") as temp:
        base = Path(temp)
        docker_smoke(args.image, base)
        if args.minikube:
            minikube_smoke(args.image, base)


if __name__ == "__main__":
    main()
