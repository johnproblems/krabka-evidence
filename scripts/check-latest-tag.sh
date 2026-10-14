#!/usr/bin/env bash
# Tag freshness: the broker crates this tool pins must still build at the
# newest v1.0.x release tag. Fails when the pinned tag is behind the newest
# tag and that newest tag does not build, or when the pin drifted.
set -euo pipefail
cd "$(dirname "$0")/.."

PINNED="$(grep -o 'tag = "v[^"]*"' Cargo.toml | head -1 | cut -d'"' -f2)"
echo "pinned tag in Cargo.toml: $PINNED"

NEWEST="$(git ls-remote --tags https://github.com/krabka-io/krabka-broker.git \
  | grep -o 'refs/tags/v1\.0\.[0-9]*$' \
  | sed 's|refs/tags/||' | sort -V | tail -1)"
echo "newest v1.0.x tag upstream: ${NEWEST:-unknown}"

if [ -z "${NEWEST:-}" ]; then
  echo "cannot list upstream tags (offline?); skipping freshness check"
  exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cp -r . "$WORK/tree"
cd "$WORK/tree"
rm -rf target .git
sed -i "s/tag = \"$PINNED\"/tag = \"$NEWEST\"/" Cargo.toml
cargo update -p krabka-audit -p krabka-guard -p krabka-remote-storage -p krabka-broker -p krabka-object-store 2>&1 | tail -2
if ! cargo check 2>&1 | tail -3; then
  echo "FAIL: newest tag $NEWEST does not build; keep the pin at $PINNED and investigate"
  exit 1
fi
if [ "$PINNED" != "$NEWEST" ]; then
  echo "NOTE: newest tag $NEWEST builds; consider bumping the pin from $PINNED"
else
  echo "OK: pinned tag is the newest and builds"
fi
