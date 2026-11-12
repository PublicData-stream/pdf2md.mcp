#!/usr/bin/env bash
set -euo pipefail
export TMPDIR=/tmp
tools=/tmp/pdf2md-ci/tools
plugins=${DOCKER_CONFIG:?}/cli-plugins
mkdir -p "$tools" "$plugins"
case "$(uname -m)" in
  x86_64)
    arch=amd64; compose_arch=x86_64
    lint_sha=6bfe0f49f0e108b9b23732baf7de63bfa4d89174fa40f9cb98feb9676df3318f
    minikube_sha=b738496da01be06bbaf80c688f57ce25acd3849fbb518155f3a88e03ef555aa4
    compose_sha=af426722a8af5de812fcee30cc1c39f0639f5f723cbadefb25e5d4db054064cf
    ;;
  aarch64)
    arch=arm64; compose_arch=aarch64
    lint_sha=81fa498f30f5dfadcc87fff0ff073281703fc56e9b50bc523b415c69aef0cccc
    minikube_sha=202f331cb677761c5aec81c58472d16d65707358b9f66226210be3fe3275b1c3
    compose_sha=f2f49f903240895fa764c0dca3a14548b754ad9426f6b609ccaf55ec5a3aa2a5
    ;;
  *) echo 'Unsupported native architecture' >&2; exit 1 ;;
esac
fetch() {
  curl --fail --location --retry 3 --output "$2" "$1"
  echo "$3  $2" | sha256sum --check --status
}
fetch "https://github.com/kjanat/actionlint/releases/download/v1.17.1/actionlint_1.17.1_linux_${arch}.tar.gz" "$tools/actionlint.tar.gz" "$lint_sha"
tar -xzf "$tools/actionlint.tar.gz" -C "$tools" actionlint
fetch "https://github.com/docker/compose/releases/download/v5.7.1/docker-compose-linux-${compose_arch}" "$plugins/docker-compose" "$compose_sha"
chmod +x "$plugins/docker-compose"
if [[ ${INSTALL_MINIKUBE:-false} == true ]]; then
  fetch "https://github.com/kubernetes/minikube/releases/download/v1.39.0/minikube-linux-${arch}" "$tools/minikube" "$minikube_sha"
  chmod +x "$tools/minikube"
fi
