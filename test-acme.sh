#!/bin/bash

set -e

# Run tests
cargo test --features acme-dns -- \
    --ignored \
    --nocapture \
    --test tests::pebble::dns::test::test_token_manager_pebble

cargo test --features acme-dns -- \
    --ignored \
    --nocapture \
    --test tls::acme::client::test::test_acme_client

cargo test --features acme-dns -- \
    --ignored \
    --nocapture \
    --test tls::acme::dns::test::test_acme_dns

# Cleanup
rm -f pebble-challtestsrv
rm -f pebble
