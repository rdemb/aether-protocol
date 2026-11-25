# AETHER Protocol — Zero-Infrastructure Communication Stack

**AETHER** is an open-source, post-quantum, zero-infrastructure communication protocol designed to operate seamlessly both with and without internet connectivity.

## Core Innovations
1. **254-Byte White-Noise Wire Format (RFC-0001):** Fixed-size packets indistinguishable from uniform random noise via Elligator-2 (+2 MSB masking), header XOR masking, GNSS-synchronized oblivious recipient tags (`O(1)` lookup), and memoryless geometric TTL decay.
2. **Post-Quantum Hybrid Key Agreement:** X25519 + NIST FIPS 203 **ML-KEM-768** tunneled over 254 B frames using RFC 6330 **RaptorQ** fountain codes.
3. **Game-Theoretic Anti-Spam & Barter (No Global Blockchain):** Asymmetric **BLAKE3-PoW** (`~50 ms` to send, `~0.5 µs` to verify), BIP-330 **Minisketch** (`GF(2^64)`) set reconciliation in a single 254 B frame, and **Tit-for-Tat** deficit-bounded exchange.
4. **Zero-Float Deterministic Semantic Compression (RFC-0002):** Integer-only `INT8`/`Q16.16` Transformer + Bresenham probability quantization + 32-bit `rANS` (< 0.80 bits/char) with optional **Basal** (`1 byte = 1 decision`) crisis mode.
5. **GNSS Pulse Duty-Cycling:** Passive GPS/Galileo time synchronization enables `< 0.4%` radio duty cycle (`~1.54 mAh/day` vs `~204 mAh/day` for continuous BLE Mesh).

## Quick Start

### 1. Run the Empirical Kineto-DTN Network Simulator (Zero Dependencies)
```bash
python3 sim/aether_sim.py
```

### 2. Compile & Run the Rust Core Compliance Suite (RFC-0001 & RFC-0002)
```bash
cargo test --release --test rfc_compliance -- --nocapture
```

### 3. Run Formal Post-Quantum Security Verification (ProVerif)
```bash
proverif formal/aether_pqxdh.pv
```

## Repository Layout
- `crates/aether-core/` — `#![forbid(unsafe_code)]` Rust reference implementation of RFC-0001 & RFC-0002.
- `crates/aether-ffi/` — C/UniFFI bindings entry point for Android (Kotlin) and iOS (Swift).
- `crates/aether-wasm/` — WebAssembly bindings for browser simulation and auditing.
- `sim/aether_sim.py` — Urban Hub-and-Commuter Monte Carlo simulator (4 km × 4 km, 30% Sybil/Free-Riders).
- `formal/aether_pqxdh.pv` — Applied pi-calculus formal verification model for ProVerif.
- `docs/` — Whitepaper v0.1, RFC-0001, and RFC-0002 specifications.

### 4. Build Phase 1 Android BLE 5.0 Coded PHY App (Kotlin + Rust JNI)
```bash
rustup target add aarch64-linux-android armv7-linux-androideabi
cargo install cargo-ndk
./scripts/build-android.sh
cd android && ./gradlew assembleDebug
```
