pub const MINISKETCH_CAPACITY: usize = 22; // 22 * 8 B = 176 B
const GF64_POLY: u64 = 0x1B; // x^64 + x^4 + x^3 + x + 1 (BIP-330)

#[inline]
pub fn gf64_mul(mut a: u64, mut b: u64) -> u64 {
    let mut res: u64 = 0;
    for _ in 0..64 {
        let mask = (b & 1).wrapping_neg();
        res ^= a & mask;
        let hi_bit = (a >> 63).wrapping_neg();
        a = (a << 1) ^ (GF64_POLY & hi_bit);
        b >>= 1;
    }
    res
}

#[inline]
pub fn gf64_sqr(a: u64) -> u64 {
    gf64_mul(a, a)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Minisketch {
    pub syndromes: [u64; MINISKETCH_CAPACITY],
}

impl Default for Minisketch {
    fn default() -> Self {
        Self::new()
    }
}

impl Minisketch {
    pub fn new() -> Self {
        Self {
            syndromes: [0u64; MINISKETCH_CAPACITY],
        }
    }

    pub fn add(&mut self, sid: u64) {
        if sid == 0 {
            return;
        }
        let sqr = gf64_sqr(sid);
        let mut cur = sid;
        for s in self.syndromes.iter_mut() {
            *s ^= cur;
            cur = gf64_mul(cur, sqr);
        }
    }

    pub fn merge(&mut self, other: &Self) {
        for (a, b) in self.syndromes.iter_mut().zip(other.syndromes.iter()) {
            *a ^= *b;
        }
    }

    pub fn to_bytes(&self) -> [u8; MINISKETCH_CAPACITY * 8] {
        let mut out = [0u8; MINISKETCH_CAPACITY * 8];
        for (i, &s) in self.syndromes.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&s.to_le_bytes());
        }
        out
    }

    pub fn from_bytes(bytes: &[u8; MINISKETCH_CAPACITY * 8]) -> Self {
        let mut syndromes = [0u64; MINISKETCH_CAPACITY];
        for i in 0..MINISKETCH_CAPACITY {
            syndromes[i] = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
        }
        Self { syndromes }
    }
}
