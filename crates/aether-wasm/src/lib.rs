#![forbid(unsafe_code)]

use aether_core::pow::verify_packet_pow;
use aether_core::wire::OuterPacket;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn verify_frame_pow_wasm(frame: &[u8], buffer_fill_pct: u8) -> i32 {
    let Ok(pkt) = OuterPacket::from_slice(frame) else {
        return -1;
    };
    match verify_packet_pow(&pkt, buffer_fill_pct) {
        Ok(bits) => bits as i32,
        Err(()) => 0,
    }
}
