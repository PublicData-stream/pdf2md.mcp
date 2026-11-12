#!/usr/bin/env python3
"""Exercise real OIDC and HTTP in a disposable isolated Minikube cluster.

Usage: python3 scripts/test-http-oidc.py IMAGE
Requires rootless Docker with its data root under /tmp, Minikube and OpenSSL.
All credentials, Kubernetes state and configuration are disposable under /tmp.
"""
import argparse
import base64
import importlib.util
import io
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import uuid
import zipfile

sys.dont_write_bytecode = True

from ci.minikube import install_shutdown, checked_cleanup, cleanup, start_args

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

provider = load("authelia_harness", "test-authelia.py")
conversion = load("conversion_harness", "test-conversion.py")
mcp = load("mcp_smoke", "mcp-smoke.py")
ISSUER = "https://127.0.0.1:9091"
SCOPE = "openid offline_access pdf2md:read pdf2md:write pdf2md:operate"


def invoke(args, *, env=None, timeout=120):
    result = subprocess.run(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        # Do not include command lines, provider responses, Kubernetes Secrets or environments.
        raise RuntimeError(Path(args[0]).name + " command failed")
    return result.stdout.decode()


def source_url(source_mode):
    if source_mode == "fixture":
        return "https://fixture.example/sample.pdf"
    if source_mode == "live":
        return "https://www.rfc-editor.org/rfc/rfc9110.pdf"
    raise RuntimeError("invalid source mode")


def config(mode, source_mode="live"):
    return f'''[mcp]
enabled = true
resource_url = "{provider.AUDIENCE}"
[auth]
mode = "oauth2"
[auth.oidc]
issuer = "{ISSUER}"
audience = "{provider.AUDIENCE}"
validation = "{mode}"
client_id = "pdf2md-opaque"
client_secret = {{ file = "/config/client-secret" }}
ca_file = "/config/ca.crt"
''' + ('access_token_prefix = "authelia_at_"\n' if mode == "introspection" else 'jwt_scope_claim = "scp"\n') + f'''[http]
published_sources = ["fixture"]
[[sources]]
id = "fixture"
mode = "obscura"
url = "{source_url(source_mode)}"
interval_secs = 3600
timeout_secs = 60
max_bytes = 10485760
'''


def generate(root, source_mode="live"):
    provider.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=pdf2md-test-ca", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash", "-keyout", str(root / "ca.key"), "-out", str(root / "ca.crt")])
    provider.run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=127.0.0.1", "-keyout", str(root / "tls.key"), "-out", str(root / "tls.csr")])
    (root / "tls.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\nauthorityKeyIdentifier=keyid,issuer\nsubjectKeyIdentifier=hash\n")
    provider.run(["openssl", "x509", "-req", "-in", str(root / "tls.csr"), "-CA", str(root / "ca.crt"), "-CAkey", str(root / "ca.key"), "-CAcreateserial", "-days", "1", "-extfile", str(root / "tls.ext"), "-out", str(root / "tls.crt")])
    provider.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(root / "oidc.key")])
    password, secret = secrets.token_urlsafe(24), secrets.token_urlsafe(32)
    users = {name: {"displayname": name, "password": provider.digest(password), "email": name + "@example.test", "groups": ["test"]} for name in ("alice", "bob")}
    clients = []
    for name, algorithm in (("opaque", "none"), ("jwt", "RS256")):
        clients.append({"client_id": "pdf2md-" + name, "client_secret": provider.digest(secret), "public": False, "redirect_uris": [provider.CALLBACK], "audience": [provider.AUDIENCE], "scopes": ["openid", "offline_access", "pdf2md:read", "pdf2md:write", "pdf2md:operate"], "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"], "authorization_policy": "one_factor", "consent_mode": "explicit", "require_pkce": True, "pkce_challenge_method": "S256", "access_token_signed_response_alg": algorithm, "lifespan": "short" if name == "jwt" else ""})
    settings = {"server": {"address": "tcp://0.0.0.0:9091", "tls": {"certificate": "/config/tls.crt", "key": "/config/tls.key"}}, "log": {"level": "warn"}, "identity_validation": {"reset_password": {"jwt_secret": secrets.token_hex(32)}}, "authentication_backend": {"file": {"path": "/config/users.yml"}}, "access_control": {"default_policy": "one_factor"}, "session": {"secret": secrets.token_hex(32), "cookies": [{"domain": "127.0.0.1", "authelia_url": ISSUER}]}, "storage": {"encryption_key": secrets.token_hex(32), "local": {"path": "/state/db.sqlite3"}}, "notifier": {"filesystem": {"filename": "/state/notifications.txt"}}, "identity_providers": {"oidc": {"hmac_secret": secrets.token_hex(32), "jwks": [{"key_id": "test-rs256", "algorithm": "RS256", "use": "sig", "key": (root / "oidc.key").read_text()}], "scopes": {s: {"claims": []} for s in ("pdf2md:read", "pdf2md:write", "pdf2md:operate")}, "lifespans": {"custom": {"short": {"access_token": "60 seconds"}}}, "clients": clients}}}
    (root / "users.yml").write_text(json.dumps({"users": users}))
    (root / "configuration.yml").write_text(json.dumps(settings))
    (root / "client-secret").write_text(secret)
    if source_mode == "fixture":
        provider.run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=fixture.example", "-keyout", str(root / "fixture.key"), "-out", str(root / "fixture.csr")])
        (root / "fixture.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:fixture.example\n")
        provider.run(["openssl", "x509", "-req", "-in", str(root / "fixture.csr"), "-CA", str(root / "ca.crt"), "-CAkey", str(root / "ca.key"), "-CAcreateserial", "-days", "1", "-extfile", str(root / "fixture.ext"), "-out", str(root / "fixture.crt")])
        (root / "sample.pdf").write_bytes(conversion.fixture())
    return password, secret


def resources(root, image, source_mode="live"):
    secret_names = ("tls.crt", "tls.key", "ca.crt", "users.yml", "configuration.yml", "client-secret")
    secret = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "provider-config"}, "type": "Opaque", "data": {name: base64.b64encode((root / name).read_bytes()).decode() for name in secret_names}}
    cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "api-config"}, "data": {"config.toml": config("introspection", source_mode)}}
    def pvc(name):
        return {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": name}, "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Gi"}}}}
    deployment = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "oidc-api"}, "spec": {"replicas": 1, "strategy": {"type": "Recreate"}, "selector": {"matchLabels": {"app": "oidc-api"}}, "template": {"metadata": {"labels": {"app": "oidc-api"}, "annotations": {"test-mode": "introspection"}}, "spec": {"securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001, "fsGroup": 10001}, "containers": [
        {"name": "provider", "image": provider.IMAGE, "ports": [{"containerPort": 9091}], "readinessProbe": {"httpGet": {"scheme": "HTTPS", "path": "/api/health", "port": 9091}, "periodSeconds": 5, "timeoutSeconds": 3}, "volumeMounts": [{"name": "provider-config", "mountPath": "/config", "readOnly": True}, {"name": "provider-state", "mountPath": "/state"}]},
        {"name": "api", "image": image, "imagePullPolicy": "Never", "args": ["--data-dir", "/data", "--config", "/etc/pdf2md/config.toml", "serve", "--listen", "0.0.0.0:8080"], "ports": [{"containerPort": 8080}], "readinessProbe": {"httpGet": {"path": "/readyz", "port": 8080}}, "volumeMounts": [{"name": "data", "mountPath": "/data"}, {"name": "api-config", "mountPath": "/etc/pdf2md", "readOnly": True}, {"name": "provider-config", "mountPath": "/config", "readOnly": True}]}
    ], "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "data"}}, {"name": "provider-state", "persistentVolumeClaim": {"claimName": "provider-state"}}, {"name": "provider-config", "secret": {"secretName": "provider-config"}}, {"name": "api-config", "configMap": {"name": "api-config"}}]}}}}
    # ConfigMap and Secret projections are symlinks; API configuration readers
    # require regular files. Copy them into pod-private volumes before startup.
    pod = deployment["spec"]["template"]["spec"]
    pod["initContainers"] = [{"name": "stage-api-config", "image": image, "imagePullPolicy": "Never", "command": ["/bin/sh", "-c", "cp /config-input/config.toml /api-config/config.toml && cp /secret-input/ca.crt /secret-input/client-secret /api-secret/ && chmod 600 /api-config/config.toml /api-secret/ca.crt /api-secret/client-secret"], "volumeMounts": [{"name": "api-config", "mountPath": "/config-input", "readOnly": True}, {"name": "provider-config", "mountPath": "/secret-input", "readOnly": True}, {"name": "api-local-config", "mountPath": "/api-config"}, {"name": "api-local-secret", "mountPath": "/api-secret"}]}]
    pod["volumes"].extend([{"name": "api-local-config", "emptyDir": {}}, {"name": "api-local-secret", "emptyDir": {}}])
    api_container = pod["containers"][1]
    api_container["volumeMounts"] = [{"name": "data", "mountPath": "/data"}, {"name": "api-local-config", "mountPath": "/etc/pdf2md", "readOnly": True}, {"name": "api-local-secret", "mountPath": "/config", "readOnly": True}]
    if source_mode == "fixture":
        fixture_secret = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "https-fixture"},
                          "type": "Opaque", "data": {name: base64.b64encode((root / name).read_bytes()).decode()
                          for name in ("ca.crt", "fixture.crt", "fixture.key", "sample.pdf")}}
        pod["volumes"].append({"name": "fixture-data", "secret": {"secretName": "https-fixture"}})
        fixture_image = os.environ.get("PDF2MD_FIXTURE_IMAGE")
        if not fixture_image:
            raise RuntimeError("fixture source mode requires PDF2MD_FIXTURE_IMAGE")
        pod["hostAliases"] = [{"ip": "93.184.216.34", "hostnames": ["fixture.example"]}]
        pod["initContainers"].insert(0, {
            "name": "fixture-local-route", "image": fixture_image, "imagePullPolicy": "Never",
            "args": ["route"],
            "securityContext": {"runAsNonRoot": False, "runAsUser": 0,
                                "allowPrivilegeEscalation": False,
                                "capabilities": {"drop": ["ALL"], "add": ["NET_ADMIN"]}}})
        pod["containers"].append({
            "name": "https-fixture", "image": fixture_image, "imagePullPolicy": "Never",
            "args": ["serve"],
            "securityContext": {"allowPrivilegeEscalation": False,
                                "capabilities": {"drop": ["ALL"], "add": ["NET_BIND_SERVICE"]}},
            "readinessProbe": {"exec": {"command": ["python3", "/fixture/server.py", "ready"]},
                               "timeoutSeconds": 5, "periodSeconds": 5},
            "volumeMounts": [{"name": "fixture-data", "mountPath": "/fixture-data", "readOnly": True}]})
        api_container["env"] = [{"name": "SSL_CERT_FILE", "value": "/config/ca.crt"}]
    path = root / "resources.json"
    items = [secret, cm, pvc("data"), pvc("provider-state"), deployment]
    if source_mode == "fixture":
        items.append(fixture_secret)
    path.write_text(json.dumps({"apiVersion": "v1", "kind": "List", "items": items}))
    path.chmod(0o600)
    return path


def api(base, method, path, token=None, data=None, content_type=None, *, timeout=30):
    headers = {}
    if token: headers["Authorization"] = "Bearer " + token
    if content_type: headers["Content-Type"] = content_type
    request = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        response = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    return response.status, response.read()


def expect(base, method, path, status, token=None, data=None, content_type=None):
    actual, body = api(base, method, path, token, data, content_type)
    if actual != status:
        raise RuntimeError(f"HTTP {method} {path.split('?')[0]}: expected {status}, got {actual}")
    return body


def poll(base, token, job, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        item = json.loads(expect(base, "GET", "/v1/jobs/" + job, 200, token))
        if item["status"] in ("succeeded", "failed", "cancelled", "interrupted"):
            return item
        time.sleep(0.5)
    raise RuntimeError("job did not reach a terminal state")


class Startup:
    """Only fixed categories and numeric/boolean status enter diagnostics."""
    def __init__(self, phase="initial"):
        self.phase = phase
        self.stage = "cluster"
        self.provider = "not_checked"
        self.api = "not_checked"
        self.forward_exit_code = None

    def check_forward(self, forward):
        code = forward.poll()
        if code is not None:
            self.forward_exit_code = code
            raise RuntimeError(f"OIDC port-forward exited (exit code {code})")

    def diagnose(self, kube):
        """Collect before deletion, without exposing logs, spec, or messages."""
        value = {"phase": self.phase, "stage": self.stage,
                 "provider": self.provider, "api": self.api,
                 "forward_exit_code": self.forward_exit_code}
        try:
            pods = json.loads(kube("get", "pods", "-l", "app=oidc-api", "-o", "json", timeout=10))["items"]
            containers = []
            for pod in pods:
                for field in ("initContainerStatuses", "containerStatuses"):
                    for container in pod.get("status", {}).get(field, []):
                        if container.get("name") not in {"provider", "api", "https-fixture", "stage-api-config", "fixture-local-route"}:
                            continue
                        state = container.get("state", {})
                        row = {"name": container["name"], "ready": container.get("ready") is True,
                               "state": next((name for name in ("waiting", "running", "terminated") if name in state), "unknown")}
                        if type(container.get("restartCount")) is int:
                            row["restarts"] = container["restartCount"]
                        for name in ("exitCode", "signal"):
                            number = state.get("terminated", {}).get(name)
                            if type(number) is int:
                                row[name] = number
                        containers.append(row)
            value["containers"] = containers
        except Exception:
            value["containers_status"] = "unavailable"
        try:
            directory = Path(os.environ.get("PDF2MD_CI_DIAGNOSTICS_DIR", "/tmp/pdf2md-ci/diagnostics"))
            if not directory.resolve().is_relative_to("/tmp"):
                raise ValueError("diagnostics must remain under /tmp")
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "oidc-startup.json").write_text(json.dumps(value, indent=2) + "\n")
        except Exception:
            print("OIDC sanitized startup diagnostics could not be written", file=sys.stderr, flush=True)


def connection_failure(error):
    reason = getattr(error, "reason", error)
    if isinstance(reason, ssl.SSLCertVerificationError):
        return "tls_verification_failure"
    if isinstance(reason, TimeoutError):
        return "timeout"
    return "connection_failure"


def ready(base, control, forward, startup, *, timeout=150):
    startup.stage = "readiness"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        startup.check_forward(forward)
        startup.provider = startup.api = "not_checked"
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            status, _, discovery = control.request("/.well-known/openid-configuration", timeout=min(5, remaining))
            startup.provider = ("unexpected_http_status" if status != 200 else
                                "invalid_discovery" if not isinstance(discovery, dict) else
                                "issuer_mismatch" if discovery.get("issuer") != ISSUER else "ready")
        except (OSError, urllib.error.URLError) as error:
            startup.provider = connection_failure(error)
        except (ValueError, UnicodeError):
            startup.provider = "invalid_discovery"
        startup.check_forward(forward)
        remaining = deadline - time.monotonic()
        if remaining > 0:
            try:
                status, _ = api(base, "GET", "/readyz", timeout=min(5, remaining))
                startup.api = "ready" if status == 200 else "unexpected_http_status"
            except (OSError, urllib.error.URLError) as error:
                startup.api = connection_failure(error)
        startup.check_forward(forward)
        if time.monotonic() < deadline and startup.provider == startup.api == "ready":
            print("PASS CA-verified OIDC discovery, issuer and forwarded HTTP readiness", flush=True)
            return
        time.sleep(max(0, min(0.5, deadline - time.monotonic())))
    raise RuntimeError(f"OIDC readiness timeout (provider={startup.provider}, api={startup.api})")


def run_test(base, control, password, secret, source_mode="live"):
    def tokens(user, client, scopes):
        return provider.Client(ISSUER, control.cert).tokens(user, password, "pdf2md-" + client, secret, scopes)
    alice = tokens("alice", "opaque", SCOPE)
    bob = tokens("bob", "opaque", SCOPE)
    readonly = tokens("alice", "opaque", "openid pdf2md:read")
    limited = tokens("alice", "opaque", "openid pdf2md:read pdf2md:write")
    a, b = alice["access_token"], bob["access_token"]
    expect(base, "GET", "/v1/history", 401)
    for kind in ("id_token", "refresh_token"):
        expect(base, "GET", "/v1/history", 401, alice[kind])
    pdf = conversion.fixture()
    expect(base, "POST", "/v1/documents", 403, readonly["access_token"], pdf, "application/pdf")
    expect(base, "POST", "/v1/sources/fixture/fetch", 403, limited["access_token"])
    result = json.loads(expect(base, "POST", "/v1/documents", 201, a, pdf, "application/pdf"))
    document, job_id = result["observation"]["document_id"], result["conversion_job"]["id"]
    expect(base, "GET", "/v1/jobs/" + job_id, 404, b)
    expect(base, "GET", "/v1/documents/" + document + "/pdf", 404, b)
    job = poll(base, a, job_id)
    if job["status"] != "succeeded": raise RuntimeError("synthetic conversion did not succeed")
    prefix = "/v1/conversions/" + job["conversion_id"]
    manifest = json.loads(expect(base, "GET", prefix + "/manifest", 200, a))
    if b"Conversion smoke test" not in expect(base, "GET", prefix + "/markdown", 200, a): raise RuntimeError("missing expected Markdown")
    assets = [x["path"] for x in manifest["artifacts"] if x["path"].startswith("assets/")]
    if not assets: raise RuntimeError("conversion asset missing")
    expect(base, "GET", prefix + "/assets/" + assets[0].removeprefix("assets/"), 200, a)
    with zipfile.ZipFile(io.BytesIO(expect(base, "GET", prefix + "/bundle.zip", 200, a))) as archive:
        if not {"manifest.json", "document.md", assets[0]}.issubset(archive.namelist()): raise RuntimeError("conversion bundle incomplete")
    markdown = expect(base, "GET", prefix + "/markdown", 200, a).decode()
    mcp.exercise(base, job["conversion_id"], markdown, readonly["access_token"], b)
    if mcp.request(base, "tools/list")[0] != 401:
        raise RuntimeError("MCP accepted missing bearer token")
    print("PASS opaque OIDC HTTP upload, conversion, bundle, scopes and workspace isolation", flush=True)
    # Report the scheduled acquisition and the explicit source request separately.
    before = {j["id"] for j in json.loads(expect(base, "GET", "/v1/jobs", 200, a))["items"]}
    scheduled_job = None
    try:
        scheduled = json.dumps({"enabled": True}).encode()
        expect(base, "PUT", "/v1/schedules/fixture", 200, a, scheduled, "application/json")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            jobs = json.loads(expect(base, "GET", "/v1/jobs", 200, a))["items"]
            scheduled_job = next((j["id"] for j in jobs if j["id"] not in before and j["kind"] == "fetch_source"), None)
            if scheduled_job: break
            time.sleep(0.25)
        if not scheduled_job: raise RuntimeError("schedule did not enqueue its source job")
    finally:
        expect(base, "PUT", "/v1/schedules/fixture", 200, a, json.dumps({"enabled": False}).encode(), "application/json")
    scheduled_result = poll(base, a, scheduled_job, timeout=120)
    body = json.loads(expect(base, "POST", "/v1/sources/fixture/fetch", 202, a))
    source_result = poll(base, a, body["id"], timeout=120)
    for name, result in (("scheduled", scheduled_result), ("explicit", source_result)):
        if result["status"] == "succeeded":
            if source_mode == "fixture":
                expected_document = hashlib.sha256(conversion.fixture()).hexdigest()
                if result.get("document_id") != expected_document:
                    raise RuntimeError("fixture browser acquisition returned unexpected PDF bytes")
                acquired = expect(base, "GET", "/v1/documents/" + expected_document + "/pdf", 200, a)
                if acquired != conversion.fixture():
                    raise RuntimeError("fixture browser acquisition PDF content does not match")
            print("PASS " + name + " configured browser source", flush=True)
        else:
            print(name.capitalize() + " configured browser source failed; sanitized error code=" + str(result.get("error_code")), flush=True)
    if scheduled_result["status"] != "succeeded" or source_result["status"] != "succeeded":
        direct = json.loads(expect(base, "POST", "/v1/acquisitions", 202, a, json.dumps({"url": source_url(source_mode)}).encode(), "application/json"))
        direct_result = poll(base, a, direct["id"], timeout=120)
        print("Direct HTTPS comparison: " + direct_result["status"] + "; sanitized error code=" + str(direct_result.get("error_code")), flush=True)
    status, _, _ = control.request("/api/oidc/revocation", {"token": a, "token_type_hint": "access_token"}, form=True, auth=("pdf2md-opaque", secret))
    if status != 200: raise RuntimeError("opaque token revocation failed")
    expect(base, "GET", "/v1/history", 401, a)
    if mcp.request(base, "tools/list", token=a)[0] != 401:
        raise RuntimeError("MCP accepted revoked opaque token")
    expect(base, "GET", "/v1/history", 200, b)
    print("PASS opaque revocation and unaffected second user", flush=True)
    return document, job_id, all(result["status"] == "succeeded" for result in (scheduled_result, source_result))


def local_config_digest(image):
    # Docker's .Id may name an OCI index, whereas Kubernetes reports the
    # platform image config. Hash the exact config blob from the saved image.
    with tempfile.TemporaryDirectory(prefix="pdf2md-image-inspect-", dir="/tmp") as tmp:
        archive = Path(tmp) / "image.tar"
        invoke(["docker", "image", "save", "--output", str(archive), image], timeout=600)
        with tarfile.open(archive, "r") as saved:
            manifest = json.load(saved.extractfile("manifest.json"))
            if len(manifest) != 1:
                raise RuntimeError("saved image did not contain exactly one platform manifest")
            blob = saved.extractfile(manifest[0]["Config"])
            if blob is None: raise RuntimeError("saved image config blob unavailable")
            digest = hashlib.sha256()
            while True:
                chunk = blob.read(1024 * 1024)
                if not chunk: break
                digest.update(chunk)
            return "sha256:" + digest.hexdigest()


def main():
    install_shutdown()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument("--source-mode", choices=("fixture", "live"), default="live")
    args = parser.parse_args()
    image = args.image
    if args.source_mode == "fixture" and not os.environ.get("PDF2MD_FIXTURE_IMAGE"):
        raise RuntimeError("fixture source mode requires PDF2MD_FIXTURE_IMAGE")
    image_index = invoke(["docker", "image", "inspect", image, "--format", "{{.Id}}"]).strip()
    expected_image_id = os.environ.get("PDF2MD_EXPECTED_IMAGE_CONFIG_DIGEST") or local_config_digest(image)
    if expected_image_id and (not expected_image_id.startswith("sha256:") or len(expected_image_id) != 71):
        raise RuntimeError("invalid expected image config digest")
    print("Local image ID " + image_index, flush=True)
    docker_root = Path(invoke(["docker", "info", "--format", "{{.DockerRootDir}}"] ).strip()).resolve()
    options = json.loads(invoke(["docker", "info", "--format", "{{json .SecurityOptions}}"] ))
    if not docker_root.is_relative_to("/tmp") or "name=rootless" not in options:
        raise RuntimeError("requires rootless Docker with its data root under /tmp")
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", 9091))
        except OSError:
            raise RuntimeError("127.0.0.1:9091 must be free before creating the cluster") from None
    with tempfile.TemporaryDirectory(prefix="pdf2md-http-oidc-", dir="/tmp") as tmp:
        root = Path(tmp)
        root.chmod(0o700)
        password, secret = generate(root, args.source_mode)
        env = os.environ.copy()
        env.update(MINIKUBE_HOME=str(root / "minikube"), KUBECONFIG=str(root / "kubeconfig"), TMPDIR="/tmp")
        for name in ("NO_PROXY", "no_proxy"):
            env[name] = env.get(name, "") + ",127.0.0.1,localhost,::1"
        profile = "pdf2md-oidc-" + uuid.uuid4().hex[:10]
        mk = ["minikube", "--profile", profile]
        def kube(*args, timeout=120):
            return invoke([*mk, "kubectl", "--", "--cache-dir", str(root / "kube-cache"), *args], env=env, timeout=timeout)
        def rollout():
            kube("rollout", "status", "deployment/oidc-api", "--timeout=240s", timeout=260)
            pods = json.loads(kube("get", "pods", "-l", "app=oidc-api", "-o", "json"))["items"]
            ids = [c["imageID"] for pod in pods if not pod["metadata"].get("deletionTimestamp") for c in pod["status"].get("containerStatuses", []) if c["name"] == "api" and c.get("ready")]
            if len(ids) != 1:
                raise RuntimeError("expected one ready API container")
            if expected_image_id and ids != [expected_image_id]:
                raise RuntimeError("running API image config digest does not match the expected build digest")
            print(("Verified" if expected_image_id else "Observed") + " API image config digest " + ids[0], flush=True)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        forwards = []
        started = False
        startup = Startup()
        def start_forward():
            proc = subprocess.Popen([*mk, "kubectl", "--", "--cache-dir", str(root / "kube-cache"), "port-forward", "deployment/oidc-api", f"{port}:8080", "9091:9091"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            forwards.append(proc)
            return proc
        def stop_forward():
            while forwards:
                proc = forwards.pop()
                proc.terminate()
                try: proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=10)
        try:
            started = True
            invoke(start_args(mk), env=env, timeout=600)
            invoke([*mk, "image", "load", image], env=env, timeout=600)
            if args.source_mode == "fixture":
                invoke([*mk, "image", "load", os.environ["PDF2MD_FIXTURE_IMAGE"]], env=env, timeout=600)
            startup.stage = "rollout"
            kube("apply", "-f", str(resources(root, image, args.source_mode)))
            rollout()
            startup.stage = "forward"
            forward = start_forward()
            control = provider.Client(ISSUER, root / "ca.crt")
            control.cert = root / "ca.crt"
            ready(base, control, forward, startup)
            startup.stage = "acceptance"
            document, job, browser_passed = run_test(base, control, password, secret, args.source_mode)
            stop_forward()
            startup = Startup("jwt")
            startup.stage = "rollout"
            cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "api-config"}, "data": {"config.toml": config("jwt", args.source_mode)}}
            (root / "jwt-config.json").write_text(json.dumps(cm))
            kube("apply", "-f", str(root / "jwt-config.json"))
            kube("rollout", "restart", "deployment/oidc-api")
            rollout()
            startup.stage = "forward"
            forward = start_forward()
            ready(base, control, forward, startup)
            startup.stage = "acceptance"
            alice = provider.Client(ISSUER, root / "ca.crt").tokens("alice", password, "pdf2md-jwt", secret, SCOPE)
            bob = provider.Client(ISSUER, root / "ca.crt").tokens("bob", password, "pdf2md-jwt", secret, SCOPE)
            jwt = alice["access_token"]
            expect(base, "GET", "/v1/jobs/" + job, 200, jwt)
            expect(base, "GET", "/v1/documents/" + document + "/pdf", 200, jwt)
            expect(base, "GET", "/v1/jobs/" + job, 404, bob["access_token"])
            for kind in ("id_token", "refresh_token"):
                expect(base, "GET", "/v1/history", 401, alice[kind])
            converted = json.loads(expect(base, "GET", "/v1/jobs/" + job, 200, jwt))["conversion_id"]
            markdown = expect(base, "GET", "/v1/conversions/" + converted + "/markdown", 200, jwt).decode()
            mcp.exercise(base, converted, markdown, jwt, bob["access_token"])
            status, _, _ = control.request("/api/oidc/revocation", {"token": jwt, "token_type_hint": "access_token"}, form=True, auth=("pdf2md-jwt", secret))
            if status != 200: raise RuntimeError("JWT revocation request failed")
            expect(base, "GET", "/v1/history", 200, jwt)
            print("PASS JWT rollout, workspace isolation and local validation after revocation", flush=True)
            claims = json.loads(base64.urlsafe_b64decode(jwt.split(".")[1] + "=="))
            remaining = max(0, claims["exp"] - time.time() + 2)
            while remaining > 0:
                duration = min(remaining, 30)
                time.sleep(duration)
                remaining = max(0, claims["exp"] - time.time() + 2)
            expect(base, "GET", "/v1/history", 401, jwt)
            if mcp.request(base, "tools/list", token=jwt)[0] != 401:
                raise RuntimeError("MCP accepted expired JWT")
            print("PASS expired JWT rejected over HTTP and MCP", flush=True)
            if not browser_passed:
                raise RuntimeError("configured browser-source acceptance did not pass")
        except BaseException:
            # Keep primary errors/cancellation intact and collect before deletion.
            startup.diagnose(kube)
            raise
        finally:
            actions = [stop_forward]
            if started:
                actions.append(lambda: checked_cleanup([*mk, "delete"], env=env))
            cleanup("disposable OIDC profile", *actions)
            print("PASS disposable Minikube profile cleanup", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.SubprocessError, OSError, ValueError, KeyError, AssertionError) as error:
        # Never print token values, request bodies, command environments or secrets.
        print("Minikube OIDC test failed: " + (str(error) if isinstance(error, RuntimeError) else type(error).__name__), flush=True)
        raise SystemExit(1) from None
