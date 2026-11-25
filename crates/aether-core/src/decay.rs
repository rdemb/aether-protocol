use rand_core::CryptoRngCore;

pub const DECAY_THRESHOLDS: [u16; 16] = [
    0x0000, // 0x0: p=0.0000 (1-hop)
    0x5555, // 0x1: p=0.3333
    0x8000, // 0x2: p=0.5000
    0xAAAA, // 0x3: p=0.6667
    0xC000, // 0x4: p=0.7500
    0xD000, // 0x5: p=0.8125
    0xD99A, // 0x6: p=0.8500
    0xE000, // 0x7: p=0.8750
    0xE666, // 0x8: p=0.9000 (Default urban DTN, E[H]=10)
    0xEB85, // 0x9: p=0.9200
    0xF000, // 0xA: p=0.9375
    0xF333, // 0xB: p=0.9500
    0xF5C3, // 0xC: p=0.9600
    0xF852, // 0xD: p=0.9700
    0xFAE1, // 0xE: p=0.9800
    0xFC29, // 0xF: p=0.9850 (Emergency)
];

pub const MAX_DTN_AGE_HOURS: u64 = 72;
pub const MAX_FUTURE_DRIFT_HOURS: u64 = 1;

pub fn should_relay_geometric(decay_class: u8, rng: &mut impl CryptoRngCore) -> bool {
    let threshold = DECAY_THRESHOLDS[(decay_class & 0x0F) as usize];
    if threshold == 0 {
        return false;
    }
    let mut sample = [0u8; 2];
    rng.fill_bytes(&mut sample);
    u16::from_le_bytes(sample) < threshold
}

pub fn resolve_gnss_epoch(current_epoch_hour: u64, epoch_lsb_plain: u8) -> Option<u64> {
    let now_lsb = (current_epoch_hour & 0xFF) as i32;
    let pkt_lsb = epoch_lsb_plain as i32;
    let mut diff = pkt_lsb - now_lsb;
    if diff > 127 {
        diff -= 256;
    } else if diff < -128 {
        diff += 256;
    }
    if diff >= -(MAX_DTN_AGE_HOURS as i32) && diff <= (MAX_FUTURE_DRIFT_HOURS as i32) {
        Some((current_epoch_hour as i64 + diff as i64) as u64)
    } else {
        None
    }
}
