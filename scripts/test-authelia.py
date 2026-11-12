#!/usr/bin/env python3
"""Run real Authelia token and caller-isolation tests with disposable local state.

Requires Docker, OpenSSL, Python 3, and the project's Rust toolchain. All generated
credentials, provider storage, certificates, and fixture output live under /tmp.
The HTTP client below is a test-only registered OIDC client; pdf2md has no login
or callback listener. The pinned provider's first-factor/consent HTTP endpoints
are used to automate two synthetic users, without a browser dependency.
"""
import base64
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

sys.dont_write_bytecode = True

from ci.minikube import install_shutdown, checked_cleanup, cleanup

IMAGE = os.environ.get("PDF2MD_AUTHELIA_IMAGE", "authelia/authelia:4.39.28@sha256:bd97cff4fcbf715b5ff1f9ae286afbe6033afce385302520b0368122d43a6f54")
AUDIENCE = "https://pdf2md.example.test/"
CALLBACK = "http://127.0.0.1:49199/callback"


def run(args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, **kwargs)


def b64(value):
    return base64.b64encode(value).decode().rstrip("=").replace("+", ".")


def digest(password):
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha512", password.encode(), salt, 310000)
    return "$pbkdf2-sha512$310000$" + b64(salt) + "$" + b64(derived)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, issuer, cert):
        self.issuer = issuer
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(self.cookies),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(cert))),
            NoRedirect(),
        )

    def request(self, path, body=None, form=False, auth=None, *, timeout=5):
        url = path if path.startswith("http") else self.issuer + path
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
            body = urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode()
        if auth:
            headers["Authorization"] = "Basic " + base64.b64encode((auth[0] + ":" + auth[1]).encode()).decode()
        request = urllib.request.Request(url, data=body, headers=headers)
        try:
            response = self.opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        payload = response.read(256 * 1024)
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            data = None
        return response.code, response.headers, data

    def tokens(self, username, password, client_id, secret, scopes):
        verifier = secrets.token_urlsafe(48)
        state = secrets.token_urlsafe(24)
        query = {
            "client_id": client_id, "redirect_uri": CALLBACK,
            "response_type": "code", "scope": scopes, "resource": AUDIENCE,
            "state": state, "nonce": secrets.token_urlsafe(24),
            "code_challenge": base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("="),
            "code_challenge_method": "S256",
        }
        authorization = self.issuer + "/api/oidc/authorization?" + urllib.parse.urlencode(query)
        status, headers, response = self.request(authorization)
        if status not in [302, 303]:
            code = response.get("error", "unknown") if isinstance(response, dict) else "non-json"
            raise RuntimeError("provider did not start the authorization flow (status=" + str(status) + ", error=" + code + ")")
        location = headers["Location"]
        flow = urllib.parse.parse_qs(urllib.parse.urlparse(location).query).get("flow_id", [None])[0]
        if not flow:
            raise RuntimeError("provider did not return a login flow ID")
        status, _, data = self.request("/api/firstfactor", {
            "username": username, "password": password, "keepMeLoggedIn": False,
            "flow": "openid_connect", "flowID": flow,
        })
        if status != 200 or not data or data.get("status") != "OK":
            raise RuntimeError("synthetic-user login failed")
        redirect = data.get("data", {}).get("redirect") or data.get("data", {}).get("redirect_uri")
        status, headers, _ = self.request(redirect or authorization)
        location = headers.get("Location", "")
        if "/consent" in location:
            flow = urllib.parse.parse_qs(urllib.parse.urlparse(location).query).get("flow_id", [flow])[0]
            status, _, data = self.request("/api/oidc/consent", {
                "flow_id": flow, "client_id": client_id, "consent": True, "pre_configure": False,
            })
            if status != 200 or not data:
                raise RuntimeError("synthetic-user consent failed")
            redirect = data.get("data", {}).get("redirect_uri")
            status, headers, _ = self.request(redirect)
            location = headers.get("Location", "")
        values = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
        if status not in [302, 303] or values.get("state") != [state] or "code" not in values:
            raise RuntimeError("provider did not return an authorization code")
        status, _, data = self.request("/api/oidc/token", {
            "grant_type": "authorization_code", "code": values["code"][0],
            "redirect_uri": CALLBACK, "code_verifier": verifier, "resource": AUDIENCE,
        }, form=True, auth=(client_id, secret))
        if status != 200 or not data or "access_token" not in data:
            raise RuntimeError("provider did not exchange the authorization code")
        return data


def main():
    install_shutdown()
    os.chdir(Path(__file__).resolve().parent.parent)
    os.environ["TMPDIR"] = "/tmp"
    os.environ["CARGO_TARGET_DIR"] = "/tmp/rust/target"
    os.environ.pop("PDF2MD_LIVE_AUTHELIA_PHASE", None)
    # Only the loopback provider bypasses an inherited outbound proxy.
    for variable in ["NO_PROXY", "no_proxy"]:
        prior = os.environ.get(variable, "")
        os.environ[variable] = (prior + "," if prior else "") + "127.0.0.1,localhost,::1"
    cargo = ["cargo", "test", "--locked", "--package", "pdf2md-mcp", "--test", "live_authelia"]
    profile = os.environ.get("PDF2MD_CARGO_PROFILE")
    if profile:
        cargo += ["--profile", profile, "--config", f'profile.{profile}.inherits="dev"']
    # Compile once and run the captured binary: short-lived token tests must not
    # trigger another build after token issuance or between revocation phases.
    executable = os.environ.get("PDF2MD_LIVE_AUTHELIA_TEST_EXECUTABLE")
    if executable:
        executable = str(Path(executable).resolve())
        if not Path(executable).is_file() or not os.access(executable, os.X_OK):
            raise RuntimeError("prebuilt Authelia test executable is unavailable")
        listed = subprocess.run([executable, "--ignored", "--list"], check=True,
                                stdout=subprocess.PIPE, text=True, timeout=30)
        if not any(line.endswith(": test") for line in listed.stdout.splitlines()):
            raise RuntimeError("prebuilt Authelia executable has no ignored tests")
    if not os.environ.get("PDF2MD_AUTHELIA_SKIP_RUST") and not executable:
        built = subprocess.run(cargo + ["--no-run", "--message-format=json"], check=True, stdout=subprocess.PIPE, text=True)
        for line in built.stdout.splitlines():
            artifact = json.loads(line)
            if artifact.get("reason") == "compiler-artifact" and artifact.get("target", {}).get("name") == "live_authelia" and artifact.get("executable"):
                executable = artifact["executable"]
        if executable is None:
            raise RuntimeError("Cargo did not produce the live acceptance test executable")
    docker = ["docker"]
    options = json.loads(run(docker + ["info", "--format", "{{json .SecurityOptions}}"]).stdout)
    user = "0:0" if any("rootless" in option for option in options) else str(os.getuid()) + ":" + str(os.getgid())
    container = "pdf2md-authelia-" + secrets.token_hex(6)
    with tempfile.TemporaryDirectory(prefix="pdf2md-authelia-", dir="/tmp") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        with socket.socket() as port_socket:
            port_socket.bind(("127.0.0.1", 0))
            port = port_socket.getsockname()[1]
        issuer = "https://127.0.0.1:" + str(port)
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=pdf2md-test-ca", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash", "-keyout", str(root / "ca.key"), "-out", str(root / "ca.crt")])
        run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=127.0.0.1", "-keyout", str(root / "tls.key"), "-out", str(root / "tls.csr")])
        (root / "tls.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\nauthorityKeyIdentifier=keyid,issuer\nsubjectKeyIdentifier=hash\n")
        run(["openssl", "x509", "-req", "-in", str(root / "tls.csr"), "-CA", str(root / "ca.crt"), "-CAkey", str(root / "ca.key"), "-CAcreateserial", "-days", "1", "-extfile", str(root / "tls.ext"), "-out", str(root / "tls.crt")])
        run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(root / "oidc.key")])
        password = secrets.token_urlsafe(24)
        client_secret = secrets.token_urlsafe(32)
        users = {name: {"displayname": name, "password": digest(password), "email": name + "@example.test", "groups": ["test"]} for name in ["alice", "bob"]}
        (root / "users.yml").write_text(json.dumps({"users": users}))
        clients = []
        for name, algorithm in [("opaque", "none"), ("jwt", "RS256")]:
            clients.append({
                "client_id": "pdf2md-" + name, "client_secret": digest(client_secret), "public": False,
                "redirect_uris": [CALLBACK], "audience": [AUDIENCE],
                "scopes": ["openid", "offline_access", "pdf2md:read", "pdf2md:write", "pdf2md:operate"],
                "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
                "authorization_policy": "one_factor", "consent_mode": "explicit",
                "require_pkce": True, "pkce_challenge_method": "S256",
                "access_token_signed_response_alg": algorithm,
                "lifespan": "short" if name == "jwt" else "",
            })
        configuration = {
            "server": {"address": "tcp://0.0.0.0:9091", "tls": {"certificate": "/config/tls.crt", "key": "/config/tls.key"}},
            "log": {"level": "warn"},
            "identity_validation": {"reset_password": {"jwt_secret": secrets.token_hex(32)}},
            "authentication_backend": {"file": {"path": "/config/users.yml"}},
            "access_control": {"default_policy": "one_factor"},
            "session": {"secret": secrets.token_hex(32), "cookies": [{"domain": "127.0.0.1", "authelia_url": issuer}]},
            "storage": {"encryption_key": secrets.token_hex(32), "local": {"path": "/config/db.sqlite3"}},
            "notifier": {"filesystem": {"filename": "/config/notifications.txt"}},
            "identity_providers": {"oidc": {
                "hmac_secret": secrets.token_hex(32),
                "jwks": [{"key_id": "test-rs256", "algorithm": "RS256", "use": "sig", "key": (root / "oidc.key").read_text()}],
                "scopes": {"pdf2md:read": {"claims": []}, "pdf2md:write": {"claims": []}, "pdf2md:operate": {"claims": []}},
                "lifespans": {"custom": {"short": {"access_token": "60 seconds"}}},
                "clients": clients,
            }},
        }
        (root / "configuration.yml").write_text(json.dumps(configuration))
        try:
            run(docker + ["run", "--detach", "--user", user, "--name", container, "--publish", "127.0.0.1:" + str(port) + ":9091", "--mount", "type=bind,src=" + str(root) + ",dst=/config", IMAGE])
            control = Client(issuer, root / "ca.crt")
            last_error = "no response"
            for _ in range(60):
                try:
                    status, _, discovery = control.request("/.well-known/openid-configuration")
                    if status == 200:
                        break
                except (OSError, urllib.error.URLError) as error:
                    reason = getattr(error, "reason", error)
                    last_error = type(reason).__name__
                    if isinstance(reason, ssl.SSLCertVerificationError):
                        last_error += ": " + reason.verify_message
                time.sleep(0.5)
            else:
                raise RuntimeError("provider failed to become ready (" + last_error + ")")
            print("Authelia ready (selected image); discovery issuer matches=" + str(discovery.get("issuer") == issuer) + "; introspection advertised=" + str("introspection_endpoint" in discovery), flush=True)
            (root / "client-secret").write_text(client_secret)
            fixture = {"secret_file": str(root / "client-secret"), "issuer": issuer, "audience": AUDIENCE, "ca_file": str(root / "ca.crt"), "client_id": "pdf2md-opaque", "client_secret": client_secret}
            for user in ["alice", "bob"]:
                for mode in ["opaque", "jwt"]:
                    client = Client(issuer, root / "ca.crt")
                    fixture[user + "_" + mode] = client.tokens(user, password, "pdf2md-" + mode, client_secret, "openid offline_access pdf2md:read pdf2md:write pdf2md:operate")
            fixture["read_only"] = Client(issuer, root / "ca.crt").tokens("alice", password, "pdf2md-opaque", client_secret, "openid pdf2md:read")
            fixture["jwt_read_only"] = Client(issuer, root / "ca.crt").tokens("alice", password, "pdf2md-jwt", client_secret, "openid pdf2md:read")
            fixture["read_write"] = Client(issuer, root / "ca.crt").tokens("alice", password, "pdf2md-opaque", client_secret, "openid pdf2md:read pdf2md:write")
            jwt_claims = json.loads(base64.urlsafe_b64decode(fixture["alice_jwt"]["access_token"].split(".")[1] + "=="))
            print("JWT fields: " + ",".join(sorted(jwt_claims)) + "; scope=" + str(jwt_claims.get("scope")) + "; scp=" + str(jwt_claims.get("scp")), flush=True)
            path = root / "fixture.json"
            path.write_text(json.dumps(fixture))
            path.chmod(0o600)
            os.environ["PDF2MD_LIVE_AUTHELIA_FIXTURE"] = str(path)
            status, _, introspection = control.request("/api/oidc/introspection", {"token": fixture["alice_opaque"]["access_token"]}, form=True, auth=("pdf2md-opaque", client_secret))
            if status != 200 or not introspection.get("active"):
                raise RuntimeError("real opaque access token did not introspect")
            print("Real Authorization Code + PKCE tokens issued for two synthetic users; introspection fields: " + ",".join(sorted(introspection)), flush=True)
            print("Introspection shape: " + json.dumps({"issuer_matches": introspection.get("iss") == issuer, "audience_matches": AUDIENCE in introspection.get("aud", []), "scope": introspection.get("scope"), "access_prefix_matches": fixture["alice_opaque"]["access_token"].startswith("authelia_at_")}), flush=True)
            for kind in ["access_token", "refresh_token", "id_token"]:
                sample = fixture["alice_opaque"][kind]
                status, _, result = control.request("/api/oidc/introspection", {"token": sample, "token_type_hint": "access_token"}, form=True, auth=("pdf2md-opaque", client_secret))
                print("Introspection token-kind check: " + kind + " active=" + str(result.get("active")) + " fields=" + ",".join(sorted(result)), flush=True)
            if os.environ.get("PDF2MD_AUTHELIA_SKIP_RUST"):
                print("Provider-only smoke complete; Rust caller acceptance was explicitly skipped", flush=True)
                return
            test = [executable, "--ignored", "--test-threads=1"]
            subprocess.run(test, check=True, timeout=120)
            status, _, _ = control.request("/api/oidc/revocation", {"token": fixture["alice_opaque"]["access_token"], "token_type_hint": "access_token"}, form=True, auth=("pdf2md-opaque", client_secret))
            if status != 200:
                raise RuntimeError("provider did not revoke the opaque token")
            os.environ["PDF2MD_LIVE_AUTHELIA_PHASE"] = "revoked"
            subprocess.run(test, check=True, timeout=120)
            jwt = fixture["alice_jwt"]["access_token"]
            claims = json.loads(base64.urlsafe_b64decode(jwt.split(".")[1] + "=="))
            expiry_wait = max(0, claims["exp"] - time.time() + 2)
            print("Waiting " + str(round(expiry_wait)) + " seconds for the live JWT expiry check", flush=True)
            time.sleep(expiry_wait)
            os.environ["PDF2MD_LIVE_AUTHELIA_PHASE"] = "expired"
            subprocess.run(test, check=True, timeout=120)
            print("Live Authelia acceptance passed: both validators, scopes, two-user isolation, revocation, JWT expiry", flush=True)
        finally:
            cleanup("disposable Authelia container",
                    lambda: checked_cleanup(docker + ["rm", "--force", container], timeout=30))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as error:
        # Never render token endpoint bodies, command environments, or credentials.
        print("Authelia test failed: " + (str(error) if isinstance(error, RuntimeError) else type(error).__name__), flush=True)
        raise SystemExit(1) from None
