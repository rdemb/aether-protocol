#!/usr/bin/env bash
set -euo pipefail
echo "=== [1/3] Running Empirical Kineto-DTN Simulator ==="
python3 sim/aether_sim.py
echo ""
echo "=== [2/3] Running Rust RFC-0001 & RFC-0002 Compliance Tests ==="
cargo test --release --test rfc_compliance -- --nocapture
echo ""
echo "=== [3/3] Checking ProVerif (if installed) ==="
if command -v proverif >/dev/null 2>&1; then
    proverif formal/aether_pqxdh.pv
else
    echo "ProVerif not installed (optional): install via 'opam install proverif'"
fi
