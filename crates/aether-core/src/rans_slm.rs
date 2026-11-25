//! Zero-float deterministic fixed-point i-Softmax, Bresenham probability quantization,
//! and 32-bit byte-renormalized rANS encoder/decoder (RFC-0002).

use thiserror::Error;

pub const VOCAB_SIZE: usize = 4096;
pub const RANS_SCALE_BITS: u32 = 14;
pub const RANS_SCALE: u32 = 1 << RANS_SCALE_BITS;
pub const RANS_L: u32 = 1 << 23;
const RANS_BUDGET: u64 = (RANS_SCALE as u64) - (VOCAB_SIZE as u64);
const LOG2_E_Q16: i64 = 94_548;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CompressionError {
    #[error("Corrupted rANS stream or final state mismatch")]
    CorruptedStream,
    #[error("Unexpected EOF while renormalizing rANS decoder")]
    UnexpectedEof,
    #[error("Token ID out of range (>= 4096)")]
    InvalidTokenId,
    #[error("Payload exceeds 182-byte RFC-0001 frame limit")]
    PayloadOverflow,
}

const fn exp2_neg_q16_exact_const(idx: u32) -> u32 {
    if idx == 0 {
        return 65536;
    }
    if idx >= 256 {
        return 32768;
    }
    let u: i64 = (idx as i64) << 8;
    let u2: i64 = (u * u) >> 16;
    let u3: i64 = (u2 * u) >> 16;
    let u4: i64 = (u3 * u) >> 16;
    let u5: i64 = (u4 * u) >> 16;
    let res = 65536i64
        - ((45426 * u) >> 16)
        + ((15743 * u2) >> 16)
        - ((3638 * u3) >> 16)
        + ((630 * u4) >> 16)
        - ((87 * u5) >> 16);
    if res < 32768 {
        32768
    } else if res > 65536 {
        65536
    } else {
        res as u32
    }
}

const EXP2_NEG_LUT: [u32; 257] = {
    let mut table = [0u32; 257];
    let mut i = 0;
    while i <= 256 {
        table[i] = exp2_neg_q16_exact_const(i as u32);
        i += 1;
    }
    table
};

pub struct RansDistribution {
    pub cdf: [u16; VOCAB_SIZE],
    pub freq: [u16; VOCAB_SIZE],
}

impl RansDistribution {
    pub fn from_logits_q16(logits: &[i32; VOCAB_SIZE]) -> Self {
        let mut max_z = i32::MIN;
        for &z in logits.iter() {
            if z > max_z {
                max_z = z;
            }
        }

        let mut weights = [0u32; VOCAB_SIZE];
        let mut sum_w: u64 = 0;

        for (i, &z) in logits.iter().enumerate() {
            let dz = (z as i64) - (max_z as i64);
            let y_q16 = (dz * LOG2_E_Q16) >> 16;
            let neg_y = (-y_q16) as u64;
            let k = neg_y >> 16;
            if k < 20 {
                let f = (neg_y & 0xFFFF) as u32;
                let idx = (f >> 8) as usize;
                let frac = f & 0xFF;
                let v0 = EXP2_NEG_LUT[idx];
                let v1 = EXP2_NEG_LUT[idx + 1];
                let exp2_frac = v0 - (((v0 - v1) * frac) >> 8);
                let w = exp2_frac >> (k as u32);
                weights[i] = w;
                sum_w += w as u64;
            }
        }

        let mut cdf = [0u16; VOCAB_SIZE];
        let mut freq = [0u16; VOCAB_SIZE];
        let mut cum_w: u64 = 0;
        let mut prev_target: u64 = 0;

        for i in 0..VOCAB_SIZE {
            cum_w += weights[i] as u64;
            let target = (cum_w * RANS_BUDGET) / sum_w;
            let extra = (target - prev_target) as u16;
            cdf[i] = (i as u16) + (prev_target as u16);
            freq[i] = 1 + extra;
            prev_target = target;
        }

        Self { cdf, freq }
    }

    pub fn find_symbol(&self, slot: u16) -> u16 {
        let mut lo: usize = 0;
        let mut hi: usize = VOCAB_SIZE;
        while lo + 1 < hi {
            let mid = lo + ((hi - lo) >> 1);
            if self.cdf[mid] <= slot {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        lo as u16
    }
}

pub fn rans_encode_sequence(symbols: &[(u16, u16)]) -> (u32, Vec<u8>) {
    let mut x: u32 = RANS_L;
    let mut stack: Vec<u8> = Vec::with_capacity(symbols.len());

    for &(cdf_k, freq_k) in symbols.iter().rev() {
        let f = freq_k as u32;
        let c = cdf_k as u32;
        let x_max = ((RANS_L >> RANS_SCALE_BITS) << 8) * f;
        while x >= x_max {
            stack.push((x & 0xFF) as u8);
            x >>= 8;
        }
        x = ((x / f) << RANS_SCALE_BITS) + (x % f) + c;
    }

    stack.reverse();
    (x, stack)
}

pub struct RansDecoder<'a> {
    state: u32,
    stream: &'a [u8],
    pos: usize,
}

impl<'a> RansDecoder<'a> {
    pub fn new(initial_state: u32, stream: &'a [u8]) -> Result<Self, CompressionError> {
        if initial_state < RANS_L || initial_state >= (RANS_L << 8) {
            return Err(CompressionError::CorruptedStream);
        }
        Ok(Self {
            state: initial_state,
            stream,
            pos: 0,
        })
    }

    pub fn decode_next(&mut self, dist: &RansDistribution) -> Result<u16, CompressionError> {
        let slot = (self.state & ((RANS_SCALE - 1) as u32)) as u16;
        let token = dist.find_symbol(slot);
        let f = dist.freq[token as usize] as u32;
        let c = dist.cdf[token as usize] as u32;

        self.state = f * (self.state >> RANS_SCALE_BITS) + ((slot as u32) - c);
        while self.state < RANS_L {
            if self.pos >= self.stream.len() {
                return Err(CompressionError::UnexpectedEof);
            }
            self.state = (self.state << 8) | (self.stream[self.pos] as u32);
            self.pos += 1;
        }
        Ok(token)
    }

    pub fn finish(self) -> Result<(), CompressionError> {
        if self.state == RANS_L && self.pos == self.stream.len() {
            Ok(())
        } else {
            Err(CompressionError::CorruptedStream)
        }
    }
}

pub fn isqrt_u64(n: u64) -> u64 {
    if n < 2 {
        return n;
    }
    let mut x = 1u64 << ((64 - n.leading_zeros() + 1) / 2);
    loop {
        let y = (x + n / x) >> 1;
        if y >= x {
            return x;
        }
        x = y;
    }
}
