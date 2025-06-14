#!/bin/bash

VER="2.8.0"

set -e

# Pebble DNS
PEBBLE_DNS_MACOS_ARM64_URL="https://github.com/letsencrypt/pebble/releases/download/v${VER}/pebble-challtestsrv-darwin-arm64.tar.gz"
PEBBLE_DNS_MACOS_ARM64_SHA="1bc5a6cfa062d9756e98d67825daf67f61dd655bcb6025efca2138fe836c9bbc"

PEBBLE_DNS_LINUX_AMD64_URL="https://github.com/letsencrypt/pebble/releases/download/v2.8.0/pebble-challtestsrv-linux-amd64.tar.gz"
PEBBLE_DNS_LINUX_AMD64_SHA="a817449d1f05ae58bcb7bf073b4cebe5d31512f859ba4b83951bd825d28d2114"

# Pebble
PEBBLE_MACOS_ARM64_URL="https://github.com/letsencrypt/pebble/releases/download/v${VER}/pebble-darwin-arm64.tar.gz"
PEBBLE_MACOS_ARM64_SHA="39e07d63dc776521f2ffe0584e5f4f081c984ac02742c882b430891d89f0c866"

PEBBLE_LINUX_AMD64_URL="https://github.com/letsencrypt/pebble/releases/download/v${VER}/pebble-linux-amd64.tar.gz"
PEBBLE_LINUX_AMD64_SHA="34595d915bbc2fc827affb3f58593034824df57e95353b031c8d5185724485ce"

# Detect OS/ARCH
if [ "$(uname -om)" == "x86_64 GNU/Linux" ]; then
    echo "Linux detected"
    PEBBLE_DNS_URL=${PEBBLE_DNS_LINUX_AMD64_URL}
    PEBBLE_DNS_SHA=${PEBBLE_DNS_LINUX_AMD64_SHA}
    PEBBLE_URL=${PEBBLE_LINUX_AMD64_URL}
    PEBBLE_SHA=${PEBBLE_LINUX_AMD64_SHA}
elif [ "$(uname -om)" == "Darwin arm64" ]; then
    echo "MacOS detected"
    PEBBLE_DNS_URL=${PEBBLE_DNS_MACOS_ARM64_URL}
    PEBBLE_DNS_SHA=${PEBBLE_DNS_MACOS_ARM64_SHA}
    PEBBLE_URL=${PEBBLE_MACOS_ARM64_URL}
    PEBBLE_SHA=${PEBBLE_MACOS_ARM64_SHA}
else
    echo "Unsupported OS/architecture"
    exit 1
fi

# Download archives & check SHA
curl -fsSL --retry 3 --retry-delay 5 "${PEBBLE_DNS_URL}" -o pebble-dns.tar.gz
echo "${PEBBLE_DNS_SHA} pebble-dns.tar.gz" | sha256sum -c -

curl -fsSL --retry 3 --retry-delay 5 "${PEBBLE_URL}" -o pebble.tar.gz
echo "${PEBBLE_SHA} pebble.tar.gz" | sha256sum -c -

# Extract binaries directly from archives bypassing deep folder structure
tar -C . -xf pebble-dns.tar.gz --transform 's/.*\///g' --wildcards --no-anchored 'pebble-challtestsrv'
tar -C . -xf pebble.tar.gz --transform 's/.*\///g' --wildcards --no-anchored 'pebble'

chmod +x pebble pebble-challtestsrv

# Run tests
cargo test -- \
    --ignored \
    --nocapture \
    --test tls::acme::client::test::test_acme_client

cargo test -- \
    --ignored \
    --nocapture \
    --test tls::acme::dns::test::test_acme_dns

# Cleanup
rm -f pebble-dns.tar.gz
rm -f pebble.tar.gz
rm -f pebble-challtestsrv
rm -f pebble
