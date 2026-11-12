#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
workspace=$(mktemp -d /tmp/pdf2md-console-lint.XXXXXXXX)
trap 'rm -rf -- "$workspace"' EXIT

mkdir -p "$workspace/project/src/http" "$workspace/tmp"
cp -- "$repo_root/package.json" "$repo_root/pnpm-lock.yaml" \
  "$repo_root/eslint.config.mjs" "$workspace/project/"
cp -- "$repo_root/src/http/docs.js" "$repo_root/src/http/oauth-implicit.js" \
  "$workspace/project/src/http/"

export TMPDIR="$workspace/tmp"
export XDG_CACHE_HOME="$workspace/cache"
export XDG_CONFIG_HOME="$workspace/config"
export XDG_DATA_HOME="$workspace/data"
export npm_config_cache="$workspace/npm-cache"
export npm_config_userconfig=/dev/null
export COREPACK_HOME="$workspace/corepack"
export PNPM_HOME="$workspace/pnpm"
cd -- "$workspace/project"

package_manager=$(node --input-type=module -e '
  import { readFileSync } from "node:fs";
  const value = JSON.parse(readFileSync("package.json", "utf8")).packageManager;
  if (typeof value !== "string" || !/^pnpm@[0-9]+\.[0-9]+\.[0-9]+$/.test(value)) {
    throw new Error("packageManager must specify an exact pnpm version");
  }
  process.stdout.write(value);
')

npm exec --yes --package="$package_manager" -- pnpm install \
  --frozen-lockfile --store-dir "$workspace/store"
npm exec --yes --package="$package_manager" -- pnpm run lint
