#!/usr/bin/env python3
"""Run real Casdoor grant, token and caller-isolation tests with disposable local state.

Requires Docker, OpenSSL, Python 3, and the project's Rust toolchain. All generated
credentials, provider storage, certificates, and fixture output live under /tmp.
Casdoor's sign-in page is a browser application; this harness calls the same
JSON sign-in API that page uses, for two synthetic users, without a browser.
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

IMAGE = os.environ.get("PDF2MD_CASDOOR_IMAGE", "casbin/casdoor:4.27.1@sha256:a0499a9e1bc0c089af79f19b16b866432bc9519a495e286ac7c558181c302b2a")
AUDIENCE = "https://pdf2md.example.test/"
ORGANIZATION = "pdf2md"
WEB_CLIENT = "pdf2md-web"
SHORT_CLIENT = "pdf2md-short"
MACHINE_CLIENT = "pdf2md-machine"
# Casdoor ignores the port when matching loopback redirect URIs.
CALLBACK = "http://127.0.0.1/oauth/callback"
SCOPE = "pdf2md:read pdf2md:write pdf2md:operate"
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


def run(args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, **kwargs)


def certificates(root, subject_alt_names="IP:127.0.0.1"):
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=pdf2md-test-ca", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash", "-keyout", str(root / "ca.key"), "-out", str(root / "ca.crt")])
    run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=127.0.0.1", "-keyout", str(root / "tls.key"), "-out", str(root / "tls.csr")])
    (root / "tls.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=" + subject_alt_names + "\nauthorityKeyIdentifier=keyid,issuer\nsubjectKeyIdentifier=hash\n")
    run(["openssl", "x509", "-req", "-in", str(root / "tls.csr"), "-CA", str(root / "ca.crt"), "-CAkey", str(root / "ca.key"), "-CAcreateserial", "-days", "1", "-extfile", str(root / "tls.ext"), "-out", str(root / "tls.crt")])


def app_conf(origin, port, state_dir):
    """Casdoor app.conf: HTTPS only, SQLite state, console logs, unprivileged ports."""
    return "\n".join([
        "appname = casdoor", "runmode = prod", "copyrequestbody = true",
        "EnableHTTP = false", "EnableHTTPS = true", "HTTPSPort = " + str(port),
        "HTTPSCertFile = /conf/tls.crt", "HTTPSKeyFile = /conf/tls.key",
        "driverName = sqlite", "dataSourceName = file:" + state_dir + "/casdoor.db?cache=shared",
        "dbName = casdoor", "origin = " + origin, "initDataFile = /conf/init_data.json",
        "initDataNewOnly = true", "logPostOnly = true", "enableGzip = false",
        'logConfig = {"adapter":"console"}', "ldapServerPort = 10389",
        "radiusServerPort = 11812", 'socks5Proxy = ""', "isDemoMode = false", "",
    ])


def init_data(secret, passwords):
    """Organization, three registered clients and two synthetic users."""
    scopes = [{"name": name, "displayName": name, "description": "pdf2md " + name.split(":")[1]}
              for name in SCOPE.split()]
    password_signin = {"name": "Password", "displayName": "Password", "rule": "All"}

    def application(name, grants, hours, redirects=(), device=False):
        methods = [password_signin] + ([{"name": "Device login", "displayName": "Device login", "rule": "All"}] if device else [])
        return {
            "owner": "admin", "name": name, "organization": ORGANIZATION, "displayName": name,
            "clientId": name, "clientSecret": secret, "redirectUris": list(redirects),
            "grantTypes": grants, "category": "Agent", "type": "MCP", "scopes": scopes,
            "tokenFormat": "JWT-Standard", "expireInHours": hours, "refreshExpireInHours": 1,
            "enablePassword": True, "enableSignUp": False, "signinMethods": methods,
            "cert": "cert-built-in",
        }
    return {
        "organizations": [{"owner": "admin", "name": ORGANIZATION, "displayName": ORGANIZATION,
                           "passwordType": "plain", "defaultApplication": WEB_CLIENT}],
        "applications": [
            application(WEB_CLIENT, ["authorization_code", "refresh_token", DEVICE_GRANT],
                        1, [CALLBACK], device=True),
            # 0.02 hours: a 72-second access-token lifetime for the expiry phase.
            application(SHORT_CLIENT, ["authorization_code"], 0.02, [CALLBACK]),
            application(MACHINE_CLIENT, ["client_credentials"], 1),
        ],
        "users": [{"owner": ORGANIZATION, "name": name, "displayName": name, "password": password,
                   "signupApplication": WEB_CLIENT, "type": "normal-user", "email": name + "@example.test"}
                  for name, password in passwords.items()],
    }


def write_provider_files(root, origin, port, state_dir, secret, passwords):
    (root / "app.conf").write_text(app_conf(origin, port, state_dir))
    (root / "init_data.json").write_text(json.dumps(init_data(secret, passwords)))


class Client:
    """Test-only automation of Casdoor's sign-in API and OAuth endpoints."""

    def __init__(self, issuer, cert):
        self.issuer = issuer
        self.cert = cert
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(self.cookies),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(cert))),
        )

    def request(self, path, body=None, form=False, auth=None, *, query=None, bearer=None, timeout=10):
        url = path if path.startswith("http") else self.issuer + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
            body = urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode()
        if auth:
            pair = urllib.parse.quote_plus(auth[0]) + ":" + urllib.parse.quote_plus(auth[1])
            headers["Authorization"] = "Basic " + base64.b64encode(pair.encode()).decode()
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        request = urllib.request.Request(url, data=body, headers=headers, method="POST" if body is not None else "GET")
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

    def sign_in(self, username, password, application, query, kind):
        """Submit credentials as Casdoor's sign-in page does for an authorization request."""
        status, _, data = self.request("/api/login", {
            "application": application, "organization": ORGANIZATION, "username": username,
            "password": password, "autoSignin": True, "type": kind,
        }, query=query)
        if status != 200 or not isinstance(data, dict) or data.get("status") != "ok" or not data.get("data"):
            raise RuntimeError("synthetic-user sign-in failed (" + str(status) + ")")
        return data

    def authorize(self, username, password, query):
        """Complete an authorization request given as the provider authorization URL's parameters."""
        kind = query["response_type"]
        mapped = {"clientId": query["client_id"], "responseType": kind, "redirectUri": query["redirect_uri"],
                  "type": "code" if kind == "code" else "token", "scope": query["scope"], "state": query["state"],
                  "nonce": secrets.token_urlsafe(16)}
        for name in ("code_challenge", "code_challenge_method", "resource"):
            if name in query:
                mapped[name] = query[name]
        return self.sign_in(username, password, query["client_id"], mapped, mapped["type"])["data"]

    def tokens(self, username, password, client_id, secret, scopes, resource=AUDIENCE):
        verifier = secrets.token_urlsafe(48)
        query = {"client_id": client_id, "redirect_uri": CALLBACK, "response_type": "code", "scope": scopes,
                 "state": secrets.token_urlsafe(24), "resource": resource, "code_challenge_method": "S256",
                 "code_challenge": base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")}
        code = self.authorize(username, password, query)
        status, _, data = self.request("/api/login/oauth/access_token", {
            "grant_type": "authorization_code", "code": code, "redirect_uri": CALLBACK,
            "code_verifier": verifier, "resource": resource,
        }, form=True, auth=(client_id, secret))
        if status != 200 or not data or "access_token" not in data:
            raise RuntimeError("provider did not exchange the authorization code")
        return data

    def client_credentials(self, client_id, secret, scopes):
        status, _, data = self.request("/api/login/oauth/access_token", {
            "grant_type": "client_credentials", "scope": scopes,
        }, form=True, auth=(client_id, secret))
        if status != 200 or not data or "access_token" not in data:
            raise RuntimeError("provider did not issue a client-credentials token")
        return data

    def approve_device(self, bearer, user_code):
        """Approve a device code with a user's existing access token."""
        status, _, data = self.request("/api/login", {
            "application": WEB_CLIENT, "organization": ORGANIZATION, "type": "device", "userCode": user_code,
        }, bearer=bearer)
        if status != 200 or not isinstance(data, dict) or data.get("status") != "ok":
            raise RuntimeError("synthetic-user device approval failed")

    def revoke(self, token, client_id, secret):
        status, _, _ = self.request("/api/login/oauth/revoke", {"token": token, "token_type_hint": "access_token"},
                                    form=True, auth=(client_id, secret))
        if status != 200:
            raise RuntimeError("provider did not revoke the access token")

    def introspect(self, token, client_id, secret):
        return self.request("/api/login/oauth/introspect", {"token": token, "token_type_hint": "access_token"},
                            form=True, auth=(client_id, secret))[2] or {}


def claims(token):
    return json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))


def wait_ready(client):
    last_error = "no response"
    for _ in range(120):
        try:
            status, _, discovery = client.request("/.well-known/openid-configuration", timeout=3)
            if status == 200:
                return discovery
        except (OSError, urllib.error.URLError) as error:
            reason = getattr(error, "reason", error)
            last_error = type(reason).__name__
            if isinstance(reason, ssl.SSLCertVerificationError):
                last_error += ": " + reason.verify_message
        time.sleep(0.5)
    raise RuntimeError("provider failed to become ready (" + last_error + ")")


def main():
    install_shutdown()
    os.chdir(Path(__file__).resolve().parent.parent)
    os.environ["TMPDIR"] = "/tmp"
    os.environ["CARGO_TARGET_DIR"] = "/tmp/rust/target"
    os.environ.pop("PDF2MD_LIVE_CASDOOR_PHASE", None)
    # Only the loopback provider bypasses an inherited outbound proxy.
    for variable in ["NO_PROXY", "no_proxy"]:
        prior = os.environ.get(variable, "")
        os.environ[variable] = (prior + "," if prior else "") + "127.0.0.1,localhost,::1"
    cargo = ["cargo", "test", "--locked", "--package", "pdf2md-mcp", "--test", "live_casdoor"]
    profile = os.environ.get("PDF2MD_CARGO_PROFILE")
    if profile:
        cargo += ["--profile", profile, "--config", f'profile.{profile}.inherits="dev"']
    # Compile once and run the captured binary: short-lived token tests must not
    # trigger another build after token issuance or between revocation phases.
    executable = os.environ.get("PDF2MD_LIVE_CASDOOR_TEST_EXECUTABLE")
    if executable:
        executable = str(Path(executable).resolve())
        if not Path(executable).is_file() or not os.access(executable, os.X_OK):
            raise RuntimeError("prebuilt Casdoor test executable is unavailable")
        listed = subprocess.run([executable, "--ignored", "--list"], check=True,
                                stdout=subprocess.PIPE, text=True, timeout=30)
        if not any(line.endswith(": test") for line in listed.stdout.splitlines()):
            raise RuntimeError("prebuilt Casdoor executable has no ignored tests")
    if not os.environ.get("PDF2MD_CASDOOR_SKIP_RUST") and not executable:
        built = subprocess.run(cargo + ["--no-run", "--message-format=json"], check=True, stdout=subprocess.PIPE, text=True)
        for line in built.stdout.splitlines():
            artifact = json.loads(line)
            if artifact.get("reason") == "compiler-artifact" and artifact.get("target", {}).get("name") == "live_casdoor" and artifact.get("executable"):
                executable = artifact["executable"]
        if executable is None:
            raise RuntimeError("Cargo did not produce the live acceptance test executable")
    docker = ["docker"]
    options = json.loads(run(docker + ["info", "--format", "{{json .SecurityOptions}}"]).stdout)
    user = "0:0" if any("rootless" in option for option in options) else str(os.getuid()) + ":" + str(os.getgid())
    container = "pdf2md-casdoor-" + secrets.token_hex(6)
    with tempfile.TemporaryDirectory(prefix="pdf2md-casdoor-", dir="/tmp") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        state = root / "state"
        state.mkdir(mode=0o700)
        with socket.socket() as port_socket:
            port_socket.bind(("127.0.0.1", 0))
            port = port_socket.getsockname()[1]
        issuer = "https://127.0.0.1:" + str(port)
        certificates(root)
        passwords = {name: secrets.token_urlsafe(24) for name in ["alice", "bob"]}
        client_secret = secrets.token_urlsafe(32)
        write_provider_files(root, issuer, 8443, "/state", client_secret, passwords)
        for name in ["app.conf", "init_data.json", "tls.crt", "tls.key", "ca.crt"]:
            (root / name).chmod(0o644)
        try:
            run(docker + ["run", "--detach", "--user", user, "--name", container,
                          "--publish", "127.0.0.1:" + str(port) + ":8443",
                          "--mount", "type=bind,src=" + str(root) + ",dst=/conf,readonly",
                          "--mount", "type=bind,src=" + str(state) + ",dst=/state", IMAGE])
            control = Client(issuer, root / "ca.crt")
            discovery = wait_ready(control)
            print("Casdoor ready (selected image); discovery issuer matches=" + str(discovery.get("issuer") == issuer)
                  + "; device endpoint advertised=" + str("device_authorization_endpoint" in discovery)
                  + "; iss response parameter=" + str(discovery.get("authorization_response_iss_parameter_supported")), flush=True)
            (root / "client-secret").write_text(client_secret)
            (root / "client-secret").chmod(0o600)
            fixture = {"secret_file": str(root / "client-secret"), "issuer": issuer, "audience": AUDIENCE,
                       "ca_file": str(root / "ca.crt"), "client_id": WEB_CLIENT, "machine_client_id": MACHINE_CLIENT,
                       "organization": ORGANIZATION, "passwords": passwords}
            for name in ["alice", "bob"]:
                fixture[name] = Client(issuer, root / "ca.crt").tokens(name, passwords[name], WEB_CLIENT, client_secret, SCOPE)
            fixture["read_only"] = Client(issuer, root / "ca.crt").tokens("alice", passwords["alice"], WEB_CLIENT, client_secret, "pdf2md:read")
            fixture["read_write"] = Client(issuer, root / "ca.crt").tokens("alice", passwords["alice"], WEB_CLIENT, client_secret, "pdf2md:read pdf2md:write")
            fixture["short"] = Client(issuer, root / "ca.crt").tokens("alice", passwords["alice"], SHORT_CLIENT, client_secret, SCOPE)
            alice = claims(fixture["alice"]["access_token"])
            print("Access-token fields: " + ",".join(sorted(alice)) + "; tokenType=" + str(alice.get("tokenType"))
                  + "; audience matches=" + str(alice.get("aud") == [AUDIENCE]), flush=True)
            intro = control.introspect(fixture["alice"]["refresh_token"], WEB_CLIENT, client_secret)
            print("Introspection reports the refresh token active=" + str(intro.get("active"))
                  + " token_type=" + str(intro.get("token_type")) + " (rejected by the casdoor token profile)", flush=True)
            path = root / "fixture.json"
            path.write_text(json.dumps(fixture))
            path.chmod(0o600)
            os.environ["PDF2MD_LIVE_CASDOOR_FIXTURE"] = str(path)
            if os.environ.get("PDF2MD_CASDOOR_SKIP_RUST"):
                print("Provider-only smoke complete; Rust caller acceptance was explicitly skipped", flush=True)
                return
            test = [executable, "--ignored", "--test-threads=1"]
            subprocess.run(test, check=True, timeout=300)
            control.revoke(fixture["alice"]["access_token"], WEB_CLIENT, client_secret)
            os.environ["PDF2MD_LIVE_CASDOOR_PHASE"] = "revoked"
            subprocess.run(test, check=True, timeout=300)
            expiry_wait = max(0, claims(fixture["short"]["access_token"])["exp"] - time.time() + 2)
            print("Waiting " + str(round(expiry_wait)) + " seconds for the live JWT expiry check", flush=True)
            time.sleep(expiry_wait)
            os.environ["PDF2MD_LIVE_CASDOOR_PHASE"] = "expired"
            subprocess.run(test, check=True, timeout=300)
            print("Live Casdoor acceptance passed: four grants, both validators, scopes, two-user isolation, revocation, JWT expiry", flush=True)
        finally:
            cleanup("disposable Casdoor container",
                    lambda: checked_cleanup(docker + ["rm", "--force", container], timeout=30))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as error:
        # Never render token endpoint bodies, command environments, or credentials.
        print("Casdoor test failed: " + (str(error) if isinstance(error, RuntimeError) else type(error).__name__), flush=True)
        raise SystemExit(1) from None
