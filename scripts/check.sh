#!/usr/bin/env bash
# Entry-point check: formatting, strict lints, and the full test suite.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo test --doc
