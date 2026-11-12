"""Shared controls for disposable smoke-test resources; never logs command data."""
import json
import os
import re
import signal
import subprocess
import sys


def install_shutdown():
    """Let main's finally blocks run when a CI cancellation sends SIGTERM."""
    def terminate(_signum, _frame):
        raise SystemExit(143)
    signal.signal(signal.SIGTERM, terminate)


def start_args(command):
    args = [*command, "start", "--driver=docker", "--cpus=2", "--memory=3072", "--container-runtime=containerd"]
    version = os.environ.get("PDF2MD_TEST_KUBERNETES_VERSION")
    if version:
        if not re.fullmatch(r"v\d+\.\d+\.\d+", version):
            raise RuntimeError("expected an exact Kubernetes version")
        args.append("--kubernetes-version=" + version)
    image = os.environ.get("PDF2MD_MINIKUBE_BASE_IMAGE")
    if image:
        args.append("--base-image=" + image)
    return args


def checked_cleanup(args, *, env=None, timeout=180):
    subprocess.run(args, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   timeout=timeout, check=True)


def cleanup(description, *actions):
    """Attempt every cleanup; preserve an active primary exception."""
    primary_failure = sys.exc_info()[0] is not None
    failed = False
    for action in actions:
        try:
            action()
        except Exception:
            failed = True
    if failed:
        message = description + " cleanup failed or is unconfirmed"
        if primary_failure:
            print(message, file=sys.stderr, flush=True)
        else:
            raise RuntimeError(message) from None


def verify_image(kube, selector, container, expected=None, namespace=None):
    expected = expected or os.environ.get("PDF2MD_EXPECTED_IMAGE_CONFIG_DIGEST")
    if not expected:
        return
    args = ["get", "pods", "-l", selector, "-o", "json"]
    if namespace:
        args += ["--namespace", namespace]
    pods = json.loads(kube(*args))["items"]
    identities = [c["imageID"].removeprefix("docker://")
                  for pod in pods if not pod["metadata"].get("deletionTimestamp")
                  for c in pod.get("status", {}).get("containerStatuses", [])
                  if c["name"] == container and c.get("imageID")]
    if identities != [expected]:
        raise RuntimeError("running container image config digest does not match the expected build")
    print("PASS running container image config digest", flush=True)
