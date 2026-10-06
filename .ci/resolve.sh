#!/usr/bin/env bash
set -euo pipefail
: "${CI:?CI only}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_NET_GIT_FETCH_WITH_CLI=true
rustc -Vv
cargo --version
date -u +%FT%TZ
cargo update
python3 .github/check-first-party.py --archive
sha256sum Cargo.lock
receipt="${CARGO_TARGET_DIR:?}/ci-receipts/${CI_COMMIT_SHA:?}"
mkdir -p "$receipt"
cp Cargo.lock "$receipt/Cargo.lock"
sha256sum "$receipt/Cargo.lock"
