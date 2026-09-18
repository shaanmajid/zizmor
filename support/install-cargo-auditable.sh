#!/usr/bin/env sh

# Install cargo-auditable for release builds. On x86_64 Linux, use a static
# binary so the same helper works in manylinux and musllinux containers.

set -eu

install="cargo install cargo-auditable --locked --version 0.7.6"

if [ "$(uname -m 2>/dev/null)" = "x86_64" ] && [ "$(uname -s 2>/dev/null)" = "Linux" ]; then
    target="x86_64-unknown-linux-musl"
    rustup target add "${target}"
    CC=gcc ${install} --target "${target}"
else
    ${install}
fi
