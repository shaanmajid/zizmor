#!/usr/bin/env sh

# Run cargo through cargo-auditable when invoked indirectly by maturin.

set -eu

if [ -n "${REAL_CARGO:-}" ]; then
    exec "${REAL_CARGO}" auditable "$@"
else
    exec cargo auditable "$@"
fi
