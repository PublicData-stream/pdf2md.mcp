#!/usr/bin/env bash
set -euo pipefail
export TMPDIR=/tmp
: "${CARGO_HOME:?}" "${RUSTUP_HOME:?}" "${GITHUB_ENV:?}" "${GITHUB_PATH:?}"
toolchain=1.99.1

# Reuse the runner's official rustup and proxies, but install toolchains and
# Cargo state into the isolated homes prepared by the composite action.
runner_rustup=$(command -v rustup) || {
  echo 'Runner-provided rustup is required' >&2
  exit 1
}
proxy_bin=$(cd -- "$(dirname -- "$runner_rustup")" && pwd -P)
for tool in rustup cargo rustc rustdoc rustfmt cargo-fmt cargo-clippy clippy-driver; do
  if [[ ! -x "$proxy_bin/$tool" ]]; then
    echo "Runner-provided Rust proxy is required: $tool" >&2
    exit 1
  fi
done
export PATH="$proxy_bin:$PATH"
export RUSTUP_TOOLCHAIN="$toolchain"
mkdir -p "$CARGO_HOME" "$RUSTUP_HOME"

rustup toolchain install "$toolchain" --profile minimal \
  --component clippy --component rustfmt --no-self-update
rustup default "$toolchain"

compiler_version=$(rustc --version)
case "$compiler_version" in
  "rustc $toolchain "*) ;;
  *) echo "Unexpected Rust compiler: $compiler_version" >&2; exit 1 ;;
esac
rustup_home=$(cd -- "$RUSTUP_HOME" && pwd -P)
sysroot=$(rustc --print sysroot)
sysroot=$(cd -- "$sysroot" && pwd -P)
case "$sysroot" in
  "$rustup_home"/toolchains/*) ;;
  *) echo 'Rust compiler sysroot is outside the isolated RUSTUP_HOME' >&2; exit 1 ;;
esac
rustup show active-toolchain
printf '%s\n' "$compiler_version"
cargo --version
cargo fmt --version
cargo clippy --version

# GitHub's environment files apply only to subsequent steps. The exports above
# also select the same proxies and toolchain during this installation step.
printf '%s\n' "$proxy_bin" >> "$GITHUB_PATH"
printf 'RUSTUP_TOOLCHAIN=%s\n' "$toolchain" >> "$GITHUB_ENV"
