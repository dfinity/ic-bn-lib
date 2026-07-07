#!/usr/bin/env bash
set -eEuo pipefail

readonly POCKETIC_VERSION="12.0.0"
readonly POCKETIC_URL="https://github.com/dfinity/pocketic/releases/download/${POCKETIC_VERSION}/pocket-ic-x86_64-linux.gz"
readonly POCKETIC_CHECKSUM="91405ba12fe8a8402cd5903fb43f5927771a5493a970cfcf3ae0dfbd8bdb45ac"
readonly WORKDIR="$(pwd)"
export POCKET_IC_BIN="${WORKDIR}/pocket-ic"
export CARGO_TARGET_DIR="${WORKDIR}/target"
export CANISTER_WASM_PATH="${CARGO_TARGET_DIR}/wasm32-unknown-unknown/release/ic_custom_domains_canister.wasm"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >&2; }

log "Downloading PocketIC v${POCKETIC_VERSION}"
curl -fsSL --retry 3 --retry-delay 5 "${POCKETIC_URL}" -o pocket-ic.gz || {
  log "Failed to download PocketIC"
  exit 1
}
echo "${POCKETIC_CHECKSUM} pocket-ic.gz" | sha256sum -c - || {
  log "PocketIC checksum verification failed"
  exit 1
}
log "Extracting PocketIC"
gzip -df pocket-ic.gz || { log "Failed to extract PocketIC"; exit 1; }
chmod +x "${POCKET_IC_BIN}" || { log "Failed to make PocketIC executable"; exit 1; }
log "PocketIC setup completed"

log "Building the canister wasm"
cargo build --package ic-custom-domains-canister --target wasm32-unknown-unknown --release || { log "Failed to build the canister wasm"; exit 1; }
log "Canister wasm built successfully at ${CANISTER_WASM_PATH}"

log "Running unit tests using all features enabled"
cargo test --all-features --profile dev --workspace --lib || { log "Unit tests failed"; exit 1; }
log "Unit tests completed successfully"

log "Running integration tests with all features enabled"
cargo test --all-features --profile dev --workspace --test '*' -- --nocapture || { log "Integration tests failed"; exit 1; }
log "Integration tests completed successfully"
