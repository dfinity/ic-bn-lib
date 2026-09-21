#!/usr/bin/env bash
set -eEuo pipefail

readonly POCKETIC_VERSION="12.0.0"
readonly WORKDIR="$(pwd)"
export POCKET_IC_BIN="${WORKDIR}/pocket-ic"
export CARGO_TARGET_DIR="${WORKDIR}/target"
export CANISTER_WASM_PATH="${CARGO_TARGET_DIR}/wasm32-unknown-unknown/release/ic_custom_domains_canister.wasm"
# Separate target dir: the `bench` feature adds test-only instrumentation endpoints that must
# never ship in the WASM used by the other (non-`--features bench`) tests above.
export BENCH_CANISTER_TARGET_DIR="${WORKDIR}/target/bench"
export BENCH_CANISTER_WASM_PATH="${BENCH_CANISTER_TARGET_DIR}/wasm32-unknown-unknown/release/ic_custom_domains_canister.wasm"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >&2; }

# `sha256sum` is GNU coreutils and is absent from a stock macOS, which ships `shasum` instead.
if command -v sha256sum >/dev/null 2>&1; then
  sha256_verify() { echo "$1  $2" | sha256sum -c -; }
else
  sha256_verify() { echo "$1  $2" | shasum -a 256 -c -; }
fi

# PocketIC publishes a separate binary per platform, so pick the one matching this host and pin
# its checksum - the same per-platform selection that `ic-bn-lib/src/tests/pebble.rs` already
# does for Pebble. Without this, any host that is not Linux/x86_64 silently downloads a binary
# it cannot exec, and every PocketIC-backed integration test fails at startup with
# "Unexpected PocketIC server version: got ``".
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)
    POCKETIC_PLATFORM="x86_64-linux"
    POCKETIC_CHECKSUM="91405ba12fe8a8402cd5903fb43f5927771a5493a970cfcf3ae0dfbd8bdb45ac" ;;
  Linux/aarch64 | Linux/arm64)
    POCKETIC_PLATFORM="arm64-linux"
    POCKETIC_CHECKSUM="5d2cac4ae21146084e4f40b0143393943cc31fe88e8af3ce008a268795e40b15" ;;
  Darwin/x86_64)
    POCKETIC_PLATFORM="x86_64-darwin"
    POCKETIC_CHECKSUM="67baa56fc4afbaa8935e14ef88d9d60f77d011947f0548adc4d424c3c8819e35" ;;
  Darwin/arm64)
    POCKETIC_PLATFORM="arm64-darwin"
    POCKETIC_CHECKSUM="4bd58559fe4516403dd3c01eb6ab0e753dad510ee113085240b8f9728a595873" ;;
  *)
    log "Unsupported platform for PocketIC: $(uname -s)/$(uname -m)"
    exit 1 ;;
esac
readonly POCKETIC_PLATFORM POCKETIC_CHECKSUM
readonly POCKETIC_URL="https://github.com/dfinity/pocketic/releases/download/${POCKETIC_VERSION}/pocket-ic-${POCKETIC_PLATFORM}.gz"

log "Downloading PocketIC v${POCKETIC_VERSION} for ${POCKETIC_PLATFORM}"
curl -fsSL --retry 3 --retry-delay 5 "${POCKETIC_URL}" -o pocket-ic.gz || {
  log "Failed to download PocketIC"
  exit 1
}
sha256_verify "${POCKETIC_CHECKSUM}" pocket-ic.gz || {
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

log "Building the canister wasm with the bench feature"
CARGO_TARGET_DIR="${BENCH_CANISTER_TARGET_DIR}" cargo build --package ic-custom-domains-canister --target wasm32-unknown-unknown --release --features bench || { log "Failed to build the bench canister wasm"; exit 1; }
log "Bench canister wasm built successfully at ${BENCH_CANISTER_WASM_PATH}"

log "Running canister interface compatibility test (without bench feature)"
cargo test --profile dev -p ic-custom-domains-canister --lib || { log "Canister unit tests failed"; exit 1; }

log "Running unit tests using all features enabled"
cargo test --all-features --profile dev --workspace --lib || { log "Unit tests failed"; exit 1; }
log "Unit tests completed successfully"

log "Running integration tests with all features enabled"
# Run with 1 thread to avoid race conditions when multiple tests run Pebble concurrently on the same port
cargo test --all-features --profile dev --workspace -- --test-threads=1 --ignored --nocapture || { log "Integration tests failed"; exit 1; }
log "Integration tests completed successfully"
