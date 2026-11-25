#!/usr/bin/env bash
set -euo pipefail
# Requires: cargo install cargo-ndk && rustup target add aarch64-linux-android armv7-linux-androideabi
cargo ndk -t arm64-v8a -t armeabi-v7a -o ./android/app/src/main/jniLibs build --release -p aether-ffi
echo "[OK] Android native libraries built in ./android/app/src/main/jniLibs"
