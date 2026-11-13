#!/usr/bin/env python3
"""Run real Keycloak grant, token and caller-isolation tests with disposable local state.

Requires Docker, OpenSSL, Python 3, and the project's Rust toolchain. All generated
credentials, certificates, the realm import and fixture output live under /tmp;
provider storage stays inside the disposable container.
Keycloak's sign-in and consent pages are HTML forms; this harness submits those
forms for two synthetic users, without a browser.
"""
import base64
import hashlib
import html
import http.cookiejar
import json
import os
from pathlib import Path
import re
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

IMAGE = os.environ.get("PDF2MD_KEYCLOAK_IMAGE", "keycloak/keycloak:26.8.2@sha256:c68e286cacd87b942ac1939a0a1481461109d6acd3a57dc496969a319a76bbf0")
AUDIENCE = "https://pdf2md.example.test/"
REALM = "pdf2md"
WEB_CLIENT = "pdf2md-web"
SHORT_CLIENT = "pdf2md-short"
MACHINE_CLIENT = "pdf2md-machine"
INTROSPECTION_CLIENT = "pdf2md-introspection"
ASSERTION_CLIENT = "pdf2md-assertion"
# Keycloak ignores the port of a loopback redirect URI (RFC 8252 section 7.3).
CALLBACK = "http://127.0.0.1/oauth/callback"
SCOPE = "pdf2md:read pdf2md:write pdf2md:operate"
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
SHORT_LIFETIME = 60


def run(args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, **kwargs)


def certificates(root, subject_alt_names="IP:127.0.0.1"):
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=pdf2md-test-ca", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash", "-keyout", str(root / "ca.key"), "-out", str(root / "ca.crt")])
    run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=127.0.0.1", "-keyout", str(root / "tls.key"), "-out", str(root / "tls.csr")])
    (root / "tls.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=" + subject_alt_names + "\nauthorityKeyIdentifier=keyid,issuer\nsubjectKeyIdentifier=hash\n")
    run(["openssl", "x509", "-req", "-in", str(root / "tls.csr"), "-CA", str(root / "ca.crt"), "-CAkey", str(root / "ca.key"), "-CAcreateserial", "-days", "1", "-extfile", str(root / "tls.ext"), "-out", str(root / "tls.crt")])


def assertion_key(root):
    """Key pair of the private_key_jwt client. The provider receives the certificate only."""
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=" + ASSERTION_CLIENT,
         "-keyout", str(root / "assertion.key"), "-out", str(root / "assertion.crt")])
    (root / "assertion.key").chmod(0o600)
    return (root / "assertion.crt").read_text()


def rsa_modulus(certificate):
    return int(run(["openssl", "x509", "-noout", "-modulus"], input=certificate.encode()).stdout.decode().strip().split("=")[1], 16)


def issuer_of(origin):
    return origin + "/realms/" + REALM


def server_args(origin, port):
    """Keycloak production mode: HTTPS only, fixed public hostname, realm import."""
    return ["start", "--import-realm", "--hostname=" + origin, "--http-enabled=false",
            "--https-port=" + str(port), "--https-certificate-file=/conf/tls.crt",
            "--https-certificate-key-file=/conf/tls.key"]


def realm(secret, passwords, assertion_certificate=None):
    """Realm with the pdf2md scopes, registered clients and two synthetic users.

    With assertion_certificate, also a private_key_jwt client.
    """
    def audience_mapper(name, key, value):
        return {"name": name, "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
                "config": {key: value, "access.token.claim": "true", "id.token.claim": "false",
                           "introspection.token.claim": "true"}}
    # Keycloak answers introspection only for a client named in the token's
    # audience, so the introspection clients join the resource URI there.
    mappers = [audience_mapper("pdf2md resource", "included.custom.audience", AUDIENCE),
               audience_mapper("pdf2md introspection", "included.client.audience", INTROSPECTION_CLIENT)]
    if assertion_certificate:
        mappers.append(audience_mapper("pdf2md assertion", "included.client.audience", ASSERTION_CLIENT))
    hidden = {"include.in.token.scope": "false", "display.on.consent.screen": "false"}
    scopes = [{"name": name, "protocol": "openid-connect", "description": "pdf2md " + name.split(":")[1],
               "attributes": {"include.in.token.scope": "true", "display.on.consent.screen": "true"}}
              for name in SCOPE.split()]
    scopes += [
        {"name": "pdf2md-resource", "protocol": "openid-connect", "attributes": hidden, "protocolMappers": mappers},
        {"name": "basic", "protocol": "openid-connect", "attributes": hidden, "protocolMappers": [
            {"name": "sub", "protocol": "openid-connect", "protocolMapper": "oidc-sub-mapper",
             "config": {"access.token.claim": "true", "introspection.token.claim": "true"}}]},
    ]

    def client(name, *, flows=False, service=False, device=False, attributes=None):
        return {
            "clientId": name, "name": name, "enabled": True, "protocol": "openid-connect",
            "publicClient": False, "clientAuthenticatorType": "client-secret", "secret": secret,
            "standardFlowEnabled": flows, "implicitFlowEnabled": False, "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": service, "fullScopeAllowed": False, "redirectUris": [CALLBACK] if flows else [], "webOrigins": [],
            "attributes": {"oauth2.device.authorization.grant.enabled": str(device).lower(), **(attributes or {})},
            "defaultClientScopes": ["basic", "pdf2md-resource"], "optionalClientScopes": SCOPE.split(),
        }
    clients = [
        # The device authorization request carries no PKCE challenge, and
        # Keycloak applies a required PKCE method to it as well.
        client(WEB_CLIENT, flows=True, device=True),
        client(SHORT_CLIENT, flows=True, attributes={
            "pkce.code.challenge.method": "S256", "access.token.lifespan": str(SHORT_LIFETIME)}),
        client(MACHINE_CLIENT, service=True),
        client(INTROSPECTION_CLIENT),
    ]
    if assertion_certificate:
        assertion = client(ASSERTION_CLIENT, service=True, attributes={
            "jwt.credential.certificate": "".join(
                line for line in assertion_certificate.splitlines() if not line.startswith("-----")),
            "token.endpoint.auth.signing.alg": "RS256"})
        assertion["clientAuthenticatorType"] = "client-jwt"
        del assertion["secret"]
        clients.append(assertion)
    return {
        "realm": REALM, "enabled": True, "sslRequired": "all",
        "accessTokenLifespan": 3600, "revokeRefreshToken": True, "refreshTokenMaxReuse": 0,
        "clientScopes": scopes, "defaultDefaultClientScopes": ["basic"], "defaultOptionalClientScopes": [],
        "clients": clients,
        "users": [{"username": name, "enabled": True, "email": name + "@example.test", "emailVerified": True,
                   "firstName": name, "lastName": "Synthetic",
                   "credentials": [{"type": "password", "value": password, "temporary": False}]}
                  for name, password in passwords.items()],
    }


def write_provider_files(root, secret, passwords, assertion_certificate=None):
    imports = root / "import"
    imports.mkdir(exist_ok=True)
    (imports / (REALM + ".json")).write_text(json.dumps(realm(secret, passwords, assertion_certificate)))
    return imports


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def form(page):
    """The action and hidden inputs of the first form of a provider page."""
    found = re.search(r"<form\b[^>]*\baction=\"([^\"]+)\"", page)
    if not found:
        raise RuntimeError("provider page has no form")
    fields = {}
    for tag in re.findall(r"<input\b[^>]*>", page):
        name = re.search(r"\bname=\"([^\"]*)\"", tag)
        value = re.search(r"\bvalue=\"([^\"]*)\"", tag)
        if name and re.search(r"\btype=\"hidden\"", tag):
            fields[html.unescape(name[1])] = html.unescape(value[1]) if value else ""
    return html.unescape(found[1]), fields


class Client:
    """Test-only automation of Keycloak's sign-in pages and OAuth endpoints."""

    def __init__(self, issuer, cert):
        self.issuer = issuer
        self.cert = cert
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(self.cookies),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(cert))),
            NoRedirect(),
        )

    def raw(self, url, body=None, auth=None, *, query=None, bearer=None, timeout=10):
        url = url if url.startswith("http") else self.issuer + url
        if query:
            url += "?" + urllib.parse.urlencode(query)
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            body = urllib.parse.urlencode(body).encode()
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
        return response.code, response.headers, response.read(256 * 1024)

    def request(self, path, body=None, auth=None, **kwargs):
        status, headers, payload = self.raw(path, body, auth, **kwargs)
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            data = None
        return status, headers, data

    def browse(self, url, body=None):
        """Follow provider redirects. Return ("page", url, html) or ("redirect", location)."""
        origin = urllib.parse.urlsplit(self.issuer)[:2]
        for _ in range(10):
            status, headers, payload = self.raw(url, body)
            body = None
            if status in (302, 303):
                location = urllib.parse.urljoin(url, headers["Location"])
                if urllib.parse.urlsplit(location)[:2] != origin:
                    return "redirect", location
                url = location
                continue
            if status != 200:
                raise RuntimeError("provider page failed (" + str(status) + ")")
            return "page", url, payload.decode()
        raise RuntimeError("provider redirected too often")

    def sign_in(self, step, username, password):
        """Submit the sign-in form, and the consent form when the provider asks."""
        for fields in ({"username": username, "password": password}, {"accept": "Yes"}):
            if step[0] != "page":
                return step
            action, hidden = form(step[2])
            step = self.browse(urllib.parse.urljoin(step[1], action), {**hidden, **fields})
        return step

    def authorize(self, username, password, query):
        """Complete an authorization request given as the provider authorization URL's parameters."""
        start = self.issuer + "/protocol/openid-connect/auth?" + urllib.parse.urlencode(query)
        step = self.sign_in(self.browse(start), username, password)
        if step[0] != "redirect":
            raise RuntimeError("synthetic-user sign-in failed")
        location = urllib.parse.urlsplit(step[1])
        result = dict(urllib.parse.parse_qsl(location.query))
        if result.get("state") != query["state"] or result.get("iss") != self.issuer or "code" not in result:
            raise RuntimeError("provider authorization response is incomplete")
        return result["code"]

    def tokens(self, username, password, client_id, secret, scopes):
        verifier = secrets.token_urlsafe(48)
        query = {"client_id": client_id, "redirect_uri": CALLBACK, "response_type": "code", "scope": "openid " + scopes,
                 "state": secrets.token_urlsafe(24), "code_challenge_method": "S256",
                 "code_challenge": base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")}
        code = self.authorize(username, password, query)
        status, _, data = self.request("/protocol/openid-connect/token", {
            "grant_type": "authorization_code", "code": code, "redirect_uri": CALLBACK, "code_verifier": verifier,
        }, auth=(client_id, secret))
        if status != 200 or not data or "access_token" not in data:
            raise RuntimeError("provider did not exchange the authorization code")
        return data

    def client_credentials(self, client_id, secret, scopes):
        status, _, data = self.request("/protocol/openid-connect/token", {
            "grant_type": "client_credentials", "scope": scopes,
        }, auth=(client_id, secret))
        if status != 200 or not data or "access_token" not in data:
            raise RuntimeError("provider did not issue a client-credentials token")
        return data

    def approve_device(self, username, password, verification_uri_complete):
        """Approve a device code as a user, through the verification and consent pages."""
        step = self.sign_in(self.browse(verification_uri_complete), username, password)
        if step[0] != "page" or not urllib.parse.urlsplit(step[1]).path.endswith("/device/status"):
            raise RuntimeError("synthetic-user device approval failed")

    def revoke(self, token, client_id, secret):
        status, _, _ = self.request("/protocol/openid-connect/revoke", {"token": token, "token_type_hint": "access_token"},
                                    auth=(client_id, secret))
        if status != 200:
            raise RuntimeError("provider did not revoke the access token")

    def introspect(self, token, client_id, secret):
        return self.request("/protocol/openid-connect/token/introspect", {"token": token, "token_type_hint": "access_token"},
                            auth=(client_id, secret))[2] or {}


def claims(token):
    return json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))


def wait_ready(client, timeout=240):
    last_error = "no response"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status, _, discovery = client.request("/.well-known/openid-configuration", timeout=3)
            if status == 200:
                return discovery
            last_error = "HTTP " + str(status)
        except (OSError, urllib.error.URLError) as error:
            reason = getattr(error, "reason", error)
            last_error = type(reason).__name__
            if isinstance(reason, ssl.SSLCertVerificationError):
                last_error += ": " + reason.verify_message
        time.sleep(1)
    raise RuntimeError("provider failed to become ready (" + last_error + ")")


def main():
    install_shutdown()
    os.chdir(Path(__file__).resolve().parent.parent)
    os.environ["TMPDIR"] = "/tmp"
    os.environ["CARGO_TARGET_DIR"] = "/tmp/rust/target"
    os.environ.pop("PDF2MD_LIVE_KEYCLOAK_PHASE", None)
    # Only the loopback provider bypasses an inherited outbound proxy.
    for variable in ["NO_PROXY", "no_proxy"]:
        prior = os.environ.get(variable, "")
        os.environ[variable] = (prior + "," if prior else "") + "127.0.0.1,localhost,::1"
    cargo = ["cargo", "test", "--locked", "--package", "pdf2md-mcp", "--test", "live_keycloak"]
    profile = os.environ.get("PDF2MD_CARGO_PROFILE")
    if profile:
        cargo += ["--profile", profile, "--config", f'profile.{profile}.inherits="dev"']
    # Compile once and run the captured binary: short-lived token tests must not
    # trigger another build after token issuance or between revocation phases.
    executable = os.environ.get("PDF2MD_LIVE_KEYCLOAK_TEST_EXECUTABLE")
    if executable:
        executable = str(Path(executable).resolve())
        if not Path(executable).is_file() or not os.access(executable, os.X_OK):
            raise RuntimeError("prebuilt Keycloak test executable is unavailable")
        listed = subprocess.run([executable, "--ignored", "--list"], check=True,
                                stdout=subprocess.PIPE, text=True, timeout=30)
        if not any(line.endswith(": test") for line in listed.stdout.splitlines()):
            raise RuntimeError("prebuilt Keycloak executable has no ignored tests")
    if not os.environ.get("PDF2MD_KEYCLOAK_SKIP_RUST") and not executable:
        built = subprocess.run(cargo + ["--no-run", "--message-format=json"], check=True, stdout=subprocess.PIPE, text=True)
        for line in built.stdout.splitlines():
            artifact = json.loads(line)
            if artifact.get("reason") == "compiler-artifact" and artifact.get("target", {}).get("name") == "live_keycloak" and artifact.get("executable"):
                executable = artifact["executable"]
        if executable is None:
            raise RuntimeError("Cargo did not produce the live acceptance test executable")
    docker = ["docker"]
    options = json.loads(run(docker + ["info", "--format", "{{json .SecurityOptions}}"]).stdout)
    # Keycloak's image grants its install directory to group 0, so any user
    # in that group can run it; the host user can then read the bind mounts.
    user = "0:0" if any("rootless" in option for option in options) else str(os.getuid()) + ":0"
    container = "pdf2md-keycloak-" + secrets.token_hex(6)
    with tempfile.TemporaryDirectory(prefix="pdf2md-keycloak-", dir="/tmp") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        with socket.socket() as port_socket:
            port_socket.bind(("127.0.0.1", 0))
            port = port_socket.getsockname()[1]
        origin = "https://127.0.0.1:" + str(port)
        issuer = issuer_of(origin)
        conf = root / "conf"
        conf.mkdir(mode=0o700)
        certificates(conf)
        passwords = {name: secrets.token_urlsafe(24) for name in ["alice", "bob"]}
        client_secret = secrets.token_urlsafe(32)
        assertion_certificate = assertion_key(root)
        imports = write_provider_files(root, client_secret, passwords, assertion_certificate)
        for name in ["tls.crt", "tls.key", "ca.crt"]:
            (conf / name).chmod(0o644)
        (imports / (REALM + ".json")).chmod(0o644)
        try:
            run(docker + ["run", "--detach", "--user", user, "--name", container,
                          "--publish", "127.0.0.1:" + str(port) + ":8443",
                          "--mount", "type=bind,src=" + str(conf) + ",dst=/conf,readonly",
                          "--mount", "type=bind,src=" + str(imports) + ",dst=/opt/keycloak/data/import,readonly",
                          IMAGE] + server_args(origin, 8443))
            control = Client(issuer, conf / "ca.crt")
            discovery = wait_ready(control)
            print("Keycloak ready (selected image); discovery issuer matches=" + str(discovery.get("issuer") == issuer)
                  + "; device endpoint advertised=" + str("device_authorization_endpoint" in discovery)
                  + "; iss response parameter=" + str(discovery.get("authorization_response_iss_parameter_supported"))
                  + "; PKCE methods=" + ",".join(discovery.get("code_challenge_methods_supported", [])), flush=True)
            # A JWT validator trusts every signing key the provider publishes.
            jwks = control.request(discovery["jwks_uri"])[2] or {}
            published = [int.from_bytes(base64.urlsafe_b64decode(key["n"] + "=="), "big")
                         for key in jwks.get("keys", []) if key.get("kty") == "RSA"]
            if not published or rsa_modulus(assertion_certificate) in published:
                raise RuntimeError("provider JWKS is empty or lists the client assertion key")
            print("Provider advertises private_key_jwt=" + str("private_key_jwt" in discovery.get("token_endpoint_auth_methods_supported", []))
                  + "; DPoP algorithms=" + ",".join(discovery.get("dpop_signing_alg_values_supported", []))
                  + "; client assertion key absent from JWKS=True", flush=True)
            (root / "client-secret").write_text(client_secret)
            (root / "client-secret").chmod(0o600)
            fixture = {"secret_file": str(root / "client-secret"), "issuer": issuer, "audience": AUDIENCE,
                       "ca_file": str(conf / "ca.crt"), "client_id": INTROSPECTION_CLIENT,
                       "web_client_id": WEB_CLIENT, "machine_client_id": MACHINE_CLIENT,
                       "assertion_client_id": ASSERTION_CLIENT, "assertion_key_file": str(root / "assertion.key"),
                       "token_endpoint": discovery["token_endpoint"], "passwords": passwords}
            for name in ["alice", "bob"]:
                fixture[name] = Client(issuer, conf / "ca.crt").tokens(name, passwords[name], WEB_CLIENT, client_secret, SCOPE)
            fixture["read_only"] = Client(issuer, conf / "ca.crt").tokens("alice", passwords["alice"], WEB_CLIENT, client_secret, "pdf2md:read")
            fixture["read_write"] = Client(issuer, conf / "ca.crt").tokens("alice", passwords["alice"], WEB_CLIENT, client_secret, "pdf2md:read pdf2md:write")
            fixture["short"] = Client(issuer, conf / "ca.crt").tokens("alice", passwords["alice"], SHORT_CLIENT, client_secret, SCOPE)
            alice = claims(fixture["alice"]["access_token"])
            audience = alice.get("aud")
            print("Access-token fields: " + ",".join(sorted(alice)) + "; typ=" + str(alice.get("typ"))
                  + "; audience includes resource=" + str(AUDIENCE in (audience if isinstance(audience, list) else [audience])), flush=True)
            intro = control.introspect(fixture["alice"]["refresh_token"], WEB_CLIENT, client_secret)
            print("Introspection by the issuing client reports the refresh token active=" + str(intro.get("active"))
                  + " typ=" + str(intro.get("typ")) + " (rejected by the keycloak token profile)", flush=True)
            path = root / "fixture.json"
            path.write_text(json.dumps(fixture))
            path.chmod(0o600)
            os.environ["PDF2MD_LIVE_KEYCLOAK_FIXTURE"] = str(path)
            if os.environ.get("PDF2MD_KEYCLOAK_SKIP_RUST"):
                print("Provider-only smoke complete; Rust caller acceptance was explicitly skipped", flush=True)
                return
            test = [executable, "--ignored", "--test-threads=1"]
            subprocess.run(test, check=True, timeout=300)
            control.revoke(fixture["alice"]["access_token"], WEB_CLIENT, client_secret)
            os.environ["PDF2MD_LIVE_KEYCLOAK_PHASE"] = "revoked"
            subprocess.run(test, check=True, timeout=300)
            expiry_wait = max(0, claims(fixture["short"]["access_token"])["exp"] - time.time() + 2)
            print("Waiting " + str(round(expiry_wait)) + " seconds for the live JWT expiry check", flush=True)
            time.sleep(expiry_wait)
            os.environ["PDF2MD_LIVE_KEYCLOAK_PHASE"] = "expired"
            subprocess.run(test, check=True, timeout=300)
            print("Live Keycloak acceptance passed: four grants, both validators, private_key_jwt, DPoP-bound tokens, scopes, two-user isolation, revocation, JWT expiry", flush=True)
        finally:
            cleanup("disposable Keycloak container",
                    lambda: checked_cleanup(docker + ["rm", "--force", container], timeout=30))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as error:
        # Never render token endpoint bodies, command environments, or credentials.
        print("Keycloak test failed: " + (str(error) if isinstance(error, RuntimeError) else type(error).__name__), flush=True)
        raise SystemExit(1) from None
