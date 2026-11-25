#!/usr/bin/env bash
set -euo pipefail
# Requires: cargo install wasm-pack
wasm-pack build crates/aether-wasm --target web --release
echo "[OK] WASM package built in crates/aether-wasm/pkg"
