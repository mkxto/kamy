#!/usr/bin/env bash
# No-transform round-trip check (grilling D23). Host-dependent (needs rustc +
# the MSVC linker on Windows), so it is NOT a cargo test; run it manually.
#
# Compiles the fixture, relocates its functions through `kamy protect
# --no-transform`, and asserts the protected binary reproduces the original's
# stdout and exit code.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
out="$root/target/roundtrip"
mkdir -p "$out"

rustc -O --edition 2021 "$root/tests/roundtrip/target.rs" -o "$out/target.exe"
cargo run -q --manifest-path "$root/Cargo.toml" -p kamy-cli -- \
    protect "$out/target.exe" --no-transform -o "$out/target.protected.exe"

orig_out="$("$out/target.exe")"; orig_rc=$?
prot_out="$("$out/target.protected.exe")"; prot_rc=$?

if [[ "$orig_out" == "$prot_out" && "$orig_rc" == "$prot_rc" ]]; then
    echo "round-trip OK: '$prot_out' (exit $prot_rc)"
else
    echo "round-trip MISMATCH" >&2
    echo "  original : '$orig_out' (exit $orig_rc)" >&2
    echo "  protected: '$prot_out' (exit $prot_rc)" >&2
    exit 1
fi
