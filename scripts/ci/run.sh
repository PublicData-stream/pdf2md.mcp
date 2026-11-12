#!/usr/bin/env bash
# Run one CI lane with disposable resources. Invoke from any working directory.
set -euo pipefail
cd "$(dirname "$0")/../.."
export TMPDIR=/tmp CARGO_TARGET_DIR=/tmp/rust/target PYTHONDONTWRITEBYTECODE=1
lane=${1:?expected CI lane}
ci_state=$(mktemp -d /tmp/pdf2md-ci-lane.XXXXXXXX)
postgres_container=
postgres_volume=
cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n $postgres_container ]]; then
    if ! docker rm --force "$postgres_container" >/dev/null 2>&1; then
      echo 'CI PostgreSQL cleanup failed or is unconfirmed' >&2
      if [[ $status == 0 ]]; then status=1; fi
    fi
  fi
  if [[ -n $postgres_volume ]]; then
    if ! docker volume rm "$postgres_volume" >/dev/null 2>&1; then
      echo 'CI PostgreSQL volume cleanup failed or is unconfirmed' >&2
      if [[ $status == 0 ]]; then status=1; fi
    fi
  fi
  if ! rm -rf "$ci_state"; then
    echo 'CI temporary-state cleanup failed or is unconfirmed' >&2
    if [[ $status == 0 ]]; then status=1; fi
  fi
  if ! python3 - "$lane" "$status" <<'DIAGNOSTICS'
import json
import os
from pathlib import Path
import re
import sys
lane, code = sys.argv[1], int(sys.argv[2])
if not re.fullmatch(r"[a-z0-9-]+", lane):
    raise SystemExit("invalid CI lane name")
directory = Path(os.environ.get("PDF2MD_CI_DIAGNOSTICS_DIR", "/tmp/pdf2md-ci/diagnostics"))
if not directory.resolve().is_relative_to("/tmp"):
    raise SystemExit("CI diagnostics must remain under /tmp")
directory.mkdir(parents=True, exist_ok=True)
value = {"lane": lane, "status": "success" if code == 0 else "failure", "exit_code": code}
(directory / (lane + ".json")).write_text(json.dumps(value, indent=2) + "\n")
DIAGNOSTICS
  then
    echo 'CI sanitized diagnostics could not be written' >&2
    if [[ $status == 0 ]]; then status=1; fi
  fi
  if [[ $status == 0 ]]; then printf 'PASS CI lane %s\n' "$lane"; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

postgres() {
  : "${PDF2MD_POSTGRES_IMAGE:?expected catalog PostgreSQL image}"
  python3 - <<'CHECK'
import json
from pathlib import Path
import subprocess
info = json.loads(subprocess.check_output(["docker", "info", "--format", "{{json .}}"], text=True))
if "name=rootless" not in info["SecurityOptions"] or not Path(info["DockerRootDir"]).resolve().is_relative_to("/tmp"):
    raise SystemExit("CI PostgreSQL requires rootless Docker with data-root under /tmp")
CHECK
  local password port
  password=$(python3 -c 'import secrets; print(secrets.token_hex(24))')
  if [[ ${GITHUB_ACTIONS:-} == true ]]; then
    echo "::add-mask::$password"
  fi
  printf 'POSTGRES_PASSWORD=%s\n' "$password" > "$ci_state/postgres.env"
  chmod 600 "$ci_state/postgres.env"
  postgres_container="pdf2md-ci-postgres-$(python3 -c 'import secrets; print(secrets.token_hex(8))')"
  postgres_volume="$postgres_container-data"
  docker volume create "$postgres_volume" >/dev/null
  docker run --detach --name "$postgres_container" \
    --env-file "$ci_state/postgres.env" \
    --publish 127.0.0.1::5432 \
    --mount "type=volume,src=$postgres_volume,dst=/var/lib/postgresql" \
    "$PDF2MD_POSTGRES_IMAGE" >/dev/null
  local ready=0
  for _ in $(seq 1 60); do
    if docker exec "$postgres_container" pg_isready --username postgres >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  if [[ $ready != 1 ]]; then
    echo 'Disposable PostgreSQL did not become ready' >&2
    return 1
  fi
  docker exec "$postgres_container" createdb --username postgres pdf2md_core
  docker exec "$postgres_container" createdb --username postgres pdf2md_migration
  port=$(docker port "$postgres_container" 5432/tcp)
  port=${port##*:}
  export PDF2MD_TEST_POSTGRES_URL="postgresql://postgres:$password@127.0.0.1:$port/pdf2md_core"
  export PDF2MD_CI_MIGRATION_URL="postgresql://postgres:$password@127.0.0.1:$port/pdf2md_migration"
}

case "$lane" in
  core-postgres)
    postgres
    cargo test --locked --package pdf2md-mcp
    PDF2MD_TEST_CONVERSION_POSTGRES_URL="$PDF2MD_CI_MIGRATION_URL" \
      cargo test --locked --package pdf2md-mcp --test conversion_storage \
      postgres_migration_bundle_export_and_namespace_isolation -- --test-threads=1 | tee "$ci_state/migration-result"
    if ! grep -Eq '^test result: ok\. 1 passed;' "$ci_state/migration-result"; then
      echo 'PostgreSQL migration test did not execute exactly once' >&2
      exit 1
    fi
    ;;
  cli)
    postgres
    python3 scripts/test-cli-docker.py "${CI_IMAGE:?expected CI image}"
    ;;
  conversion) python3 scripts/test-conversion.py "${CI_IMAGE:?expected CI image}" ;;
  http) python3 scripts/test-http.py "${CI_IMAGE:?expected CI image}" ;;
  browser) scripts/test-browser.sh ;;
  casdoor) python3 scripts/test-casdoor.py ;;
  k8s-conversion) python3 scripts/test-conversion.py "${CI_IMAGE:?expected CI image}" --minikube ;;
  k8s-http) python3 scripts/test-http.py "${CI_IMAGE:?expected CI image}" --minikube ;;
  k8s-oidc) python3 scripts/test-http-oidc.py "${CI_IMAGE:?expected CI image}" --source-mode fixture ;;
  browser-extended) RUN_LARGE_PDF_TESTS=1 RUN_SLOW_BROWSER_TESTS=1 scripts/test-browser.sh ;;
  oidc-live) python3 scripts/test-http-oidc.py "${CI_IMAGE:?expected CI image}" --source-mode live ;;
  *) echo "unknown CI lane: $lane" >&2; exit 2 ;;
esac
