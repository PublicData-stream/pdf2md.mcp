#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export TMPDIR=/tmp CARGO_TARGET_DIR=/tmp/rust/target
fixture_dir=$(mktemp -d /tmp/pdf2md-browser-test.XXXXXXXX)
trap 'rm -rf "$fixture_dir"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=fixture.example' \
  -addext 'subjectAltName=DNS:fixture.example' -keyout "$fixture_dir/key.pem" \
  -out "$fixture_dir/cert.pem" >/dev/null 2>&1
openssl x509 -in "$fixture_dir/cert.pem" -outform der -out "$fixture_dir/cert.der"
openssl pkcs8 -topk8 -nocrypt -in "$fixture_dir/key.pem" -outform der -out "$fixture_dir/key.der"
export SSL_CERT_FILE="$fixture_dir/cert.pem"
export PDF2MD_TEST_CERT_FILE="$fixture_dir/cert.der"
export PDF2MD_TEST_KEY_FILE="$fixture_dir/key.der"
export PDF2MD_TEST_WORKER="$CARGO_TARGET_DIR/debug/pdf2md-obscura-worker"
cargo build -p pdf2md-obscura-worker --locked
cargo test -p pdf2md-mcp --lib browser_e2e --locked -- --ignored --test-threads=1 --skip browser_e2e_large --skip browser_e2e_slow | tee "$fixture_dir/test-output"
if ! grep -Eq "^test result: ok\. [1-9][0-9]* passed;" "$fixture_dir/test-output"; then
  echo "browser integration tests did not run" >&2
  exit 1
fi

if [[ ${RUN_LARGE_PDF_TESTS:-0} == 1 ]]; then
  cargo test -p pdf2md-mcp --lib browser_e2e_large --locked -- --ignored --test-threads=1 | tee "$fixture_dir/large-test-output"
  if ! grep -Eq "^test result: ok\. [1-9][0-9]* passed;" "$fixture_dir/large-test-output"; then
    echo "large browser integration tests did not run" >&2
    exit 1
  fi
fi

if [[ ${RUN_SLOW_BROWSER_TESTS:-0} == 1 ]]; then
  cargo test -p pdf2md-mcp --lib browser_e2e_slow --locked -- --ignored --test-threads=1 | tee "$fixture_dir/slow-test-output"
  if ! grep -Eq "^test result: ok\. [1-9][0-9]* passed;" "$fixture_dir/slow-test-output"; then
    echo "slow browser integration tests did not run" >&2
    exit 1
  fi
fi
