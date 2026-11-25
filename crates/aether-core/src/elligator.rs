//! Constant-time Elligator-2 encoding/decoding for Curve25519 (RFC-0001 Section 4)
//! using self-contained 5-limb radix-2^51 arithmetic over F_p (p = 2^255 - 19).

use rand_core::CryptoRngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

const MASK51: u64 = (1u64 << 51) - 1;
const CURVE_A: u64 = 486_662;

/// Field element modulo p = 2^255 - 19 in 5 limbs of 51 bits.
#[derive(Clone, Copy, Debug)]
struct Fe([u64; 5]);

impl ConditionallySelectable for Fe {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Fe([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
            u64::conditional_select(&a.0[4], &b.0[4], choice),
        ])
    }
}

impl Fe {
    const ZERO: Fe = Fe([0, 0, 0, 0, 0]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0]);
    const TWO: Fe = Fe([2, 0, 0, 0, 0]);
    const A: Fe = Fe([CURVE_A, 0, 0, 0, 0]);

    fn from_bytes(bytes: &[u8; 32]) -> Self {
        let load64 = |i: usize| -> u64 {
            u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap())
        };
        let t0 = load64(0);
        let t1 = load64(8);
        let t2 = load64(16);
        let t3 = load64(24);

        let l0 = t0 & MASK51;
        let l1 = ((t0 >> 51) | (t1 << 13)) & MASK51;
        let l2 = ((t1 >> 38) | (t2 << 26)) & MASK51;
        let l3 = ((t2 >> 25) | (t3 << 39)) & MASK51;
        let l4 = (t3 >> 12) & MASK51; // masks top bit (mod 2^255)
        Fe([l0, l1, l2, l3, l4])
    }

    fn reduce(mut self) -> Self {
        let mut c = self.0[0] >> 51;
        self.0[0] &= MASK51;
        self.0[1] += c;
        c = self.0[1] >> 51;
        self.0[1] &= MASK51;
        self.0[2] += c;
        c = self.0[2] >> 51;
        self.0[2] &= MASK51;
        self.0[3] += c;
        c = self.0[3] >> 51;
        self.0[3] &= MASK51;
        self.0[4] += c;
        c = self.0[4] >> 51;
        self.0[4] &= MASK51;
        self.0[0] += c * 19;
        c = self.0[0] >> 51;
        self.0[0] &= MASK51;
        self.0[1] += c;
        self
    }

    fn to_bytes(self) -> [u8; 32] {
        let mut h = self.reduce();
        // Canonical reduction mod p = 2^255 - 19
        let mut q = (h.0[0] + 19) >> 51;
        q = (h.0[1] + q) >> 51;
        q = (h.0[2] + q) >> 51;
        q = (h.0[3] + q) >> 51;
        q = (h.0[4] + q) >> 51;

        h.0[0] += 19 * q;
        let mut c = h.0[0] >> 51;
        h.0[0] &= MASK51;
        h.0[1] += c;
        c = h.0[1] >> 51;
        h.0[1] &= MASK51;
        h.0[2] += c;
        c = h.0[2] >> 51;
        h.0[2] &= MASK51;
        h.0[3] += c;
        c = h.0[3] >> 51;
        h.0[3] &= MASK51;
        h.0[4] += c;
        h.0[4] &= MASK51;

        let mut out = [0u8; 32];
        let w0 = h.0[0] | (h.0[1] << 51);
        let w1 = (h.0[1] >> 13) | (h.0[2] << 38);
        let w2 = (h.0[2] >> 26) | (h.0[3] << 25);
        let w3 = (h.0[3] >> 39) | (h.0[4] << 12);
        out[0..8].copy_from_slice(&w0.to_le_bytes());
        out[8..16].copy_from_slice(&w1.to_le_bytes());
        out[16..24].copy_from_slice(&w2.to_le_bytes());
        out[24..32].copy_from_slice(&w3.to_le_bytes());
        out
    }

    fn add(self, rhs: Self) -> Self {
        Fe([
            self.0[0] + rhs.0[0],
            self.0[1] + rhs.0[1],
            self.0[2] + rhs.0[2],
            self.0[3] + rhs.0[3],
            self.0[4] + rhs.0[4],
        ])
        .reduce()
    }

    fn neg(self) -> Self {
        let a = self.reduce();
        // 2*p - a
        Fe([
            ((1u64 << 52) - 38) - a.0[0],
            ((1u64 << 52) - 2) - a.0[1],
            ((1u64 << 52) - 2) - a.0[2],
            ((1u64 << 52) - 2) - a.0[3],
            ((1u64 << 52) - 2) - a.0[4],
        ])
        .reduce()
    }

    fn sub(self, rhs: Self) -> Self {
        self.add(rhs.neg())
    }

    fn mul(self, rhs: Self) -> Self {
        let a = self.0;
        let b = rhs.0;
        let a0 = a[0] as u128;
        let a1 = a[1] as u128;
        let a2 = a[2] as u128;
        let a3 = a[3] as u128;
        let a4 = a[4] as u128;

        let b0 = b[0] as u128;
        let b1 = b[1] as u128;
        let b2 = b[2] as u128;
        let b3 = b[3] as u128;
        let b4 = b[4] as u128;

        let b1_19 = b1 * 19;
        let b2_19 = b2 * 19;
        let b3_19 = b3 * 19;
        let b4_19 = b4 * 19;

        let mut t0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19;
        let mut t1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19;
        let mut t2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19;
        let mut t3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19;
        let mut t4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

        let m = MASK51 as u128;
        t1 += t0 >> 51;
        t0 &= m;
        t2 += t1 >> 51;
        t1 &= m;
        t3 += t2 >> 51;
        t2 &= m;
        t4 += t3 >> 51;
        t3 &= m;
        t0 += (t4 >> 51) * 19;
        t4 &= m;
        t1 += t0 >> 51;
        t0 &= m;

        Fe([t0 as u64, t1 as u64, t2 as u64, t3 as u64, t4 as u64])
    }

    fn sq(self) -> Self {
        self.mul(self)
    }

    fn pow_n_sq(mut self, n: usize) -> Self {
        for _ in 0..n {
            self = self.sq();
        }
        self
    }

    /// Computes self^(2^252 - 3) for inverse & square-root primitives.
    fn pow22523(self) -> Self {
        let t0 = self.sq();
        let t1 = t0.pow_n_sq(2);
        let t2 = self.mul(t1);
        let t3 = t0.mul(t2);
        let t4 = t3.sq();
        let t5 = t2.mul(t4);
        let t6 = t5.pow_n_sq(5);
        let t7 = t6.mul(t5);
        let t8 = t7.pow_n_sq(10);
        let t9 = t8.mul(t7);
        let t10 = t9.pow_n_sq(20);
        let t11 = t10.mul(t9);
        let t12 = t11.pow_n_sq(10);
        let t13 = t12.mul(t7);
        let t14 = t13.pow_n_sq(50);
        let t15 = t14.mul(t13);
        let t16 = t15.pow_n_sq(100);
        let t17 = t16.mul(t15);
        let t18 = t17.pow_n_sq(50);
        let t19 = t18.mul(t13);
        let t20 = t19.pow_n_sq(2);
        t20.mul(self)
    }

    /// Computes self^(p - 2) mod p (modular inverse).
    fn inv(self) -> Self {
        // p - 2 = 2^255 - 21 = 8*(2^252 - 3) + 3
        let p22523 = self.pow22523();
        let t = p22523.pow_n_sq(3); // self^(8*(2^252 - 3))
        let s3 = self.sq().mul(self); // self^3
        t.mul(s3)
    }

    /// Legendre symbol: self^((p - 1) / 2) mod p.
    fn legendre(self) -> Self {
        // (p - 1)/2 = 2^254 - 10 = 4*(2^252 - 3) + 2
        let p22523 = self.pow22523();
        let t = p22523.pow_n_sq(2);
        t.mul(self.sq())
    }

    fn is_zero(self) -> Choice {
        self.to_bytes().ct_eq(&[0u8; 32])
    }

    fn ct_eq(self, other: Self) -> Choice {
        self.to_bytes().ct_eq(&other.to_bytes())
    }

    /// Constant-time square root returning (is_square, canonical root <= (p-1)/2).
    fn sqrt_canonical(self) -> (Choice, Self) {
        // r = self^((p + 3) / 8) = self^(2^252 - 2) = self * self^(2^252 - 3)
        let mut r = self.mul(self.pow22523());
        // sqrt(-1) = 2^((p - 1) / 4) mod p
        let sqrt_m1 = Fe::from_bytes(&[
            0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
            0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
            0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
            0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
        ]);
        let check = r.sq().ct_eq(self);
        let alt = r.mul(sqrt_m1);
        r = Fe::conditional_select(&alt, &r, check);
        let is_sq = r.sq().ct_eq(self);

        // Select canonical root r <= (p-1)/2:
        // Note: r > (p-1)/2 iff 2*r >= p, i.e., if (r + r) wraps or simply bit 254 / compare to (p-1)/2.
        // Simpler: compare canonical bytes against (p-1)/2 = 2^254 - 10.
        let r_bytes = r.to_bytes();
        let neg_r = r.neg();
        // (p - 1) / 2 in LE: [0xF6, 0xFF, ..., 0xFF, 0x3F]
        let mut half_p = [0xFFu8; 32];
        half_p[0] = 0xF6;
        half_p[31] = 0x3F;
        // Constant-time greater-than check r_bytes > half_p (from MSB to LSB)
        let mut gt = Choice::from(0u8);
        let mut eq = Choice::from(1u8);
        for i in (0..32).rev() {
            let a = r_bytes[i];
            let b = half_p[i];
            let a_gt_b = Choice::from((a > b) as u8);
            let a_eq_b = a.ct_eq(&b);
            gt |= eq & a_gt_b;
            eq &= a_eq_b;
        }
        let canon = Fe::conditional_select(&r, &neg_r, gt);
        (is_sq, canon)
    }
}

/// Decodes a 32-byte Elligator-2 representative (with 2 random MSB masking bits)
/// into a Curve25519 X25519 public key u-coordinate in constant time (RFC-0001 Sec 4.2).
pub fn elligator2_decode(ephemeral_rep: &[u8; 32]) -> PublicKey {
    let mut masked = *ephemeral_rep;
    masked[31] &= 0x3F; // Strip 2 random MSB masking bits (bits 254..255)
    let r = Fe::from_bytes(&masked);
    let r2 = r.sq();
    let denom = Fe::ONE.add(Fe::TWO.mul(r2));
    let d = Fe::A.neg().mul(denom.inv());
    // e = d^3 + A*d^2 + d
    let d2 = d.sq();
    let e = d2.mul(d).add(Fe::A.mul(d2)).add(d);
    let eps = e.legendre();

    let use_d = eps.ct_eq(Fe::ONE) | d.is_zero();
    let alt_u = d.neg().sub(Fe::A);
    let u = Fe::conditional_select(&alt_u, &d, use_d);
    PublicKey::from(u.to_bytes())
}

/// Encodes an eligible X25519 public key into a 32-byte uniform Elligator-2 representative
/// with 2 CSPRNG bits injected into bits 254..255 (RFC-0001 Sec 4.1).
pub fn elligator2_encode(pub_key: &PublicKey, rng: &mut impl CryptoRngCore) -> Option<[u8; 32]> {
    let u = Fe::from_bytes(pub_key.as_bytes());
    let u_plus_a = u.add(Fe::A);
    if bool::from(u_plus_a.is_zero()) {
        return None;
    }

    let mut rand_byte = [0u8; 1];
    rng.fill_bytes(&mut rand_byte);
    let s_bit = rand_byte[0] & 1;
    let rand_hi = (rand_byte[0] >> 1) & 0b11;

    let ratio = if s_bit == 0 {
        u.neg().mul(Fe::TWO.mul(u_plus_a).inv())
    } else {
        u_plus_a.neg().mul(Fe::TWO.mul(u).inv())
    };
    let (is_sq, r) = ratio.sqrt_canonical();
    if !bool::from(is_sq) {
        return None;
    }

    let mut out = r.to_bytes();
    out[31] = (out[31] & 0x3F) | (rand_hi << 6);
    Some(out)
}

/// Generates a fresh X25519 ephemeral keypair guaranteed to have a uniform Elligator-2 representative.
pub fn generate_elligator2_ephemeral(rng: &mut impl CryptoRngCore) -> (StaticSecret, PublicKey, [u8; 32]) {
    loop {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let sk = StaticSecret::from(seed);
        seed.zeroize();
        let pk = PublicKey::from(&sk);
        if let Some(rep) = elligator2_encode(&pk, rng) {
            return (sk, pk, rep);
        }
    }
}
