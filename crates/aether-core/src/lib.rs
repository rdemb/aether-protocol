#![forbid(unsafe_code)]
//! # AETHER Core — Reference Implementation (RFC-0001 & RFC-0002)
//!
//! Pure-Rust, zero-unsafe protocol kernel implementing:
//! - 254-byte outer wire format & 190-byte inner plaintext (`wire`)
//! - Asymmetric BLAKE3 Proof-of-Work (`pow`)
//! - Memoryless geometric TTL & GNSS epoch windowing (`decay`)
//! - Constant-time Curve25519 Elligator-2 with 2-MSB masking (`elligator`)
//! - GNSS-synchronized O(1) oblivious recipient tags (`tag`)
//! - Hybrid X25519 + NIST FIPS 203 ML-KEM-768 PQXDH with RaptorQ (`pqxdh`)
//! - BIP-330 Minisketch algebraic reconciliation over GF(2^64) (`minisketch`)
//! - Normative DTN state machine & Tit-for-Tat barter (`dtn`)
//! - Zero-float fixed-point i-Softmax & 32-bit rANS engine (`rans_slm`)

pub mod decay;
pub mod dtn;
pub mod elligator;
pub mod minisketch;
pub mod pow;
pub mod pqxdh;
pub mod rans_slm;
pub mod tag;
pub mod wire;

pub mod ultrasonic_css;
pub mod messenger;
