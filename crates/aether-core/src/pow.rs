use blake3::Hasher;
use crate::wire::{compute_header_mask, OuterPacket, PACKET_SIZE};

pub const POW_DIFFICULTY_MIN: u8 = 18;
pub const POW_DIFFICULTY_LONG_RANGE: u8 = 20;

/// Returns required leading zero bits based on decay_class and DTN buffer fill %.
pub fn required_difficulty(decay_class: u8, buffer_fill_pct: u8) -> u8 {
    let base = if decay_class >= 0x0C {
        POW_DIFFICULTY_LONG_RANGE
    } else {
        POW_DIFFICULTY_MIN
    };
    if buffer_fill_pct > 80 {
        base.saturating_add((buffer_fill_pct - 80) / 5)
    } else {
        base
    }
}

pub fn count_leading_zero_bits(hash: &[u8; 32]) -> u8 {
    let mut zeros: u8 = 0;
    for &byte in hash {
        if byte == 0 {
            zeros = zeros.saturating_add(8);
        } else {
            zeros = zeros.saturating_add(byte.leading_zeros() as u8);
            break;
        }
    }
    zeros
}

pub fn compute_body_hash(
    raw: &[u8; PACKET_SIZE],
    ctrl_plain: u8,
    epoch_lsb_plain: u8,
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"AETHER_BODY_v1");
    h.update(&raw[0..40]);
    h.update(&[ctrl_plain, epoch_lsb_plain]);
    h.update(&raw[48..254]);
    *h.finalize().as_bytes()
}

pub fn compute_pow_hash(body_hash: &[u8; 32], pow_nonce: &[u8; 6]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"AETHER_POW_v1");
    h.update(body_hash);
    h.update(pow_nonce);
    *h.finalize().as_bytes()
}

/// Verifies asymmetric BLAKE3-PoW (~0.5 us on ARMv8).
pub fn verify_packet_pow(packet: &OuterPacket, buffer_fill_pct: u8) -> Result<u8, ()> {
    let (ctrl, epoch_lsb) = packet.unmask_ctrl_and_epoch().map_err(|_| ())?;
    let required = required_difficulty(ctrl.decay_class, buffer_fill_pct);
    let body_hash = compute_body_hash(&packet.raw, ctrl.to_u8(), epoch_lsb);
    let pow_hash = compute_pow_hash(&body_hash, packet.pow_nonce());
    let achieved = count_leading_zero_bits(&pow_hash);
    if achieved >= required {
        Ok(achieved)
    } else {
        Err(())
    }
}

/// Mines a 48-bit pow_nonce and applies header XOR masking to bytes 46..47.
pub fn seal_packet_with_pow(
    raw: &mut [u8; PACKET_SIZE],
    ctrl_plain: u8,
    epoch_lsb_plain: u8,
    difficulty: u8,
    start_nonce: u64,
) -> [u8; 6] {
    let body_hash = compute_body_hash(raw, ctrl_plain, epoch_lsb_plain);
    let mut counter = start_nonce & 0x0000_FFFF_FFFF_FFFF;
    loop {
        let full = counter.to_be_bytes();
        let nonce: [u8; 6] = full[2..8].try_into().unwrap();
        let pow_hash = compute_pow_hash(&body_hash, &nonce);
        if count_leading_zero_bits(&pow_hash) >= difficulty {
            raw[40..46].copy_from_slice(&nonce);
            let ephemeral_rep: [u8; 32] = raw[8..40].try_into().unwrap();
            let mask = compute_header_mask(&ephemeral_rep, &nonce);
            raw[46] = ctrl_plain ^ mask[0];
            raw[47] = epoch_lsb_plain ^ mask[1];
            return nonce;
        }
        counter = counter.wrapping_add(1) & 0x0000_FFFF_FFFF_FFFF;
    }
}
