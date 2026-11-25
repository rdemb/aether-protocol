//! AETHER L0 Channel 3: Ultrasonic 19.5 kHz Chirp Spread Spectrum (CSS) Acoustic Modem
//! with Interleaved GF(2^8) Reed-Solomon FEC (AETHER-IMPL-0003).
//!
//! Operates in 100% Airplane Mode (Bluetooth OFF, Wi-Fi OFF, Cellular OFF) using
//! standard 48 kHz PCM-16 smartphone speaker & microphone hardware in 18.3 - 20.7 kHz.
//! Pure Rust, zero external DSP crates, `#![forbid(unsafe_code)]`.

use std::f64::consts::PI;
use thiserror::Error;

pub const SAMPLE_RATE: usize = 48_000;
pub const CARRIER_HZ: f64 = 19_500.0;
pub const BANDWIDTH_HZ: f64 = 2_400.0;
pub const DECIM: usize = 20; // 48_000 / 2_400 exact integer
pub const SF: usize = 6;
pub const M_CHIPS: usize = 1 << SF; // 64 orthogonal chirp bins (6 bits/symbol)
pub const SAMPLES_PER_SYM: usize = M_CHIPS * DECIM; // 1280 samples = 26.67 ms

pub const AETHER_FRAME_BYTES: usize = 254;
pub const BASAL_SOS_BYTES: usize = 16;
const RS_PARITY_BYTES: usize = 16; // Corrects up to 8 corrupted bytes per RS block

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AcousticError {
    #[error("Audio buffer too short to contain an AETHER ultrasonic frame")]
    BufferTooShort,
    #[error("Preamble not detected or SNR below decode threshold")]
    SyncFailed,
    #[error("Reed-Solomon FEC exceeded error correction capacity (> 8 bytes/block)")]
    FecUncorrectable,
}

// ============================================================================
// GF(2^8) Arithmetic & Reed-Solomon Encoder/Decoder (poly 0x11D, FCR = 0)
// ============================================================================
struct Gf256 {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Gf256 {
    fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255 {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if (x & 0x100) != 0 {
                x ^= 0x11D;
            }
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        Self { exp, log }
    }

    #[inline]
    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        self.exp[(self.log[a as usize] as usize) + (self.log[b as usize] as usize)]
    }

    #[inline]
    fn div(&self, a: u8, b: u8) -> u8 {
        debug_assert!(b != 0);
        if a == 0 {
            return 0;
        }
        self.exp[(self.log[a as usize] as usize + 255 - self.log[b as usize] as usize) % 255]
    }

    #[inline]
    fn pow(&self, a: u8, power: usize) -> u8 {
        if power == 0 {
            return 1;
        }
        if a == 0 {
            return 0;
        }
        self.exp[((self.log[a as usize] as usize) * (power % 255)) % 255]
    }

    fn poly_mul_desc(&self, p: &[u8], q: &[u8]) -> Vec<u8> {
        let mut r = vec![0u8; p.len() + q.len() - 1];
        for (j, &qv) in q.iter().enumerate() {
            for (i, &pv) in p.iter().enumerate() {
                r[i + j] ^= self.mul(pv, qv);
            }
        }
        r
    }

    fn poly_eval_desc(&self, poly: &[u8], x: u8) -> u8 {
        let mut y = poly[0];
        for &c in &poly[1..] {
            y = self.mul(y, x) ^ c;
        }
        y
    }

    fn poly_eval_asc(&self, poly: &[u8], x: u8) -> u8 {
        let mut y = 0u8;
        let mut xp = 1u8;
        for &c in poly {
            y ^= self.mul(c, xp);
            xp = self.mul(xp, x);
        }
        y
    }

    fn rs_encode(&self, msg: &[u8], nsym: usize) -> Vec<u8> {
        let mut gen = vec![1u8];
        for i in 0..nsym {
            gen = self.poly_mul_desc(&gen, &[1, self.pow(2, i)]);
        }
        let mut out = vec![0u8; msg.len() + nsym];
        out[..msg.len()].copy_from_slice(msg);
        for i in 0..msg.len() {
            let coef = out[i];
            if coef != 0 {
                for j in 1..gen.len() {
                    out[i + j] ^= self.mul(gen[j], coef);
                }
            }
        }
        out[..msg.len()].copy_from_slice(msg);
        out
    }

    fn rs_decode(&self, codeword: &[u8], nsym: usize) -> Result<Vec<u8>, AcousticError> {
        let mut msg = codeword.to_vec();
        let n = msg.len();
        if n <= nsym {
            return Err(AcousticError::FecUncorrectable);
        }

        let mut synd = vec![0u8; nsym];
        let mut has_err = false;
        for i in 0..nsym {
            synd[i] = self.poly_eval_desc(&msg, self.pow(2, i));
            if synd[i] != 0 {
                has_err = true;
            }
        }
        if !has_err {
            msg.truncate(n - nsym);
            return Ok(msg);
        }

        // Berlekamp-Massey (ascending powers)
        let mut c_poly = vec![1u8];
        let mut b_poly = vec![1u8];
        let mut l: usize = 0;
        let mut m: usize = 1;
        let mut b_val: u8 = 1;

        for step in 0..nsym {
            let mut d = synd[step];
            for i in 1..=l {
                d ^= self.mul(c_poly[i], synd[step - i]);
            }
            if d == 0 {
                m += 1;
            } else {
                let t_poly = c_poly.clone();
                let coef = self.div(d, b_val);
                if c_poly.len() < b_poly.len() + m {
                    c_poly.resize(b_poly.len() + m, 0);
                }
                for (i, &bv) in b_poly.iter().enumerate() {
                    c_poly[i + m] ^= self.mul(coef, bv);
                }
                if 2 * l <= step {
                    l = step + 1 - l;
                    b_poly = t_poly;
                    b_val = d;
                    m = 1;
                } else {
                    m += 1;
                }
            }
        }

        if l * 2 > nsym {
            return Err(AcousticError::FecUncorrectable);
        }
        let lam = &c_poly[..=l];

        // Chien search
        let mut err_pos = Vec::with_capacity(l);
        for pos in 0..n {
            let power = n - 1 - pos;
            let x_inv = self.pow(2, (255 - (power % 255)) % 255);
            if self.poly_eval_asc(lam, x_inv) == 0 {
                err_pos.push(pos);
            }
        }
        if err_pos.len() != l {
            return Err(AcousticError::FecUncorrectable);
        }

        // Omega(x) = S(x) * Lambda(x) mod x^nsym
        let mut omega = vec![0u8; nsym];
        for i in 0..nsym {
            let mut acc = 0u8;
            let lim = (i + 1).min(lam.len());
            for j in 0..lim {
                acc ^= self.mul(lam[j], synd[i - j]);
            }
            omega[i] = acc;
        }

        // Forney error magnitude evaluation (FCR = 0)
        for &pos in &err_pos {
            let power = n - 1 - pos;
            let x_k = self.pow(2, power % 255);
            let x_inv = self.pow(2, (255 - (power % 255)) % 255);
            let num = self.poly_eval_asc(&omega, x_inv);
            let mut den = 0u8;
            let mut xp = 1u8;
            let x2 = self.mul(x_inv, x_inv);
            let mut j = 1;
            while j < lam.len() {
                den ^= self.mul(lam[j], xp);
                xp = self.mul(xp, x2);
                j += 2;
            }
            if den == 0 {
                return Err(AcousticError::FecUncorrectable);
            }
            msg[pos] ^= self.mul(x_k, self.div(num, den));
        }

        // Verify post-correction zero syndromes
        for i in 0..nsym {
            if self.poly_eval_desc(&msg, self.pow(2, i)) != 0 {
                return Err(AcousticError::FecUncorrectable);
            }
        }
        msg.truncate(n - nsym);
        Ok(msg)
    }
}

// ============================================================================
// Complex Baseband Primitives & Chirp Synthesizer
// ============================================================================
#[derive(Clone, Copy, Default)]
struct C64 {
    re: f64,
    im: f64,
}

impl C64 {
    #[inline]
    fn from_polar(angle: f64) -> Self {
        Self {
            re: angle.cos(),
            im: angle.sin(),
        }
    }

    #[inline]
    fn add(self, o: Self) -> Self {
        Self {
            re: self.re + o.re,
            im: self.im + o.im,
        }
    }

    #[inline]
    fn mul(self, o: Self) -> Self {
        Self {
            re: self.re * o.re - self.im * o.im,
            im: self.re * o.im + self.im * o.re,
        }
    }

    #[inline]
    fn mag(self) -> f64 {
        (self.re * self.re + self.im * self.im).sqrt()
    }
}

fn synth_chirp_f64(symbol: u8, down: bool, out: &mut Vec<f64>) {
    let mut phase = 0.0f64;
    let dt = 1.0 / (SAMPLE_RATE as f64);
    let n_f = SAMPLES_PER_SYM as f64;
    let sym_shift = (symbol as f64) / (M_CHIPS as f64);

    for k in 0..SAMPLES_PER_SYM {
        let u = (k as f64) / n_f;
        let frac = if !down {
            (u + sym_shift).rem_euclid(1.0)
        } else {
            (1.0 - u).rem_euclid(1.0)
        };
        let f_inst = CARRIER_HZ + BANDWIDTH_HZ * (frac - 0.5);
        let env = if k < 32 {
            0.5 * (1.0 - (PI * (k as f64) / 32.0).cos())
        } else if k >= SAMPLES_PER_SYM - 32 {
            0.5 * (1.0 - (PI * ((SAMPLES_PER_SYM - 1 - k) as f64) / 32.0).cos())
        } else {
            1.0
        };
        out.push(env * phase.cos());
        phase += 2.0 * PI * f_inst * dt;
    }
}

fn downconvert_symbol(audio: &[f64], start_idx: usize) -> [C64; M_CHIPS] {
    let mut bb = [C64::default(); M_CHIPS];
    let inv_fs = 1.0 / (SAMPLE_RATE as f64);
    let inv_decim = 1.0 / (DECIM as f64);

    for n in 0..M_CHIPS {
        let mut acc = C64::default();
        let base = n * DECIM;
        for d in 0..DECIM {
            let k = base + d;
            let t = ((start_idx + k) as f64) * inv_fs;
            let angle = -2.0 * PI * CARRIER_HZ * t;
            let s = audio[start_idx + k];
            acc.re += s * angle.cos();
            acc.im += s * angle.sin();
        }
        bb[n] = C64 {
            re: acc.re * inv_decim,
            im: acc.im * inv_decim,
        };
    }
    bb
}

fn ref_chirps() -> ([C64; M_CHIPS], [C64; M_CHIPS]) {
    let mut down_conj = [C64::default(); M_CHIPS];
    let mut up_conj = [C64::default(); M_CHIPS];
    let m_f = M_CHIPS as f64;
    for n in 0..M_CHIPS {
        let nf = n as f64;
        let phi = 2.0 * PI * ((nf * nf) / (2.0 * m_f) - 0.5 * nf);
        down_conj[n] = C64::from_polar(-phi);
        up_conj[n] = C64::from_polar(phi);
    }
    (down_conj, up_conj)
}

fn dft_64_mags(vec: &[C64; M_CHIPS]) -> [f64; M_CHIPS] {
    let mut mags = [0.0f64; M_CHIPS];
    let m_f = M_CHIPS as f64;
    for k in 0..M_CHIPS {
        let mut acc = C64::default();
        let kf = k as f64;
        for n in 0..M_CHIPS {
            let tw = C64::from_polar(-2.0 * PI * kf * (n as f64) / m_f);
            acc = acc.add(vec[n].mul(tw));
        }
        mags[k] = acc.mag();
    }
    mags
}

fn peak_and_ratio(mags: &[f64; M_CHIPS]) -> (u8, f64) {
    let mut best_k = 0usize;
    let mut best_v = -1.0f64;
    let mut sum = 0.0f64;
    for (i, &v) in mags.iter().enumerate() {
        sum += v;
        if v > best_v {
            best_v = v;
            best_k = i;
        }
    }
    let mean_other = (sum - best_v) / ((M_CHIPS - 1) as f64);
    (best_k as u8, best_v / (mean_other + 1e-9))
}

fn bytes_to_6bit_symbols(data: &[u8]) -> Vec<u8> {
    let mut syms = Vec::with_capacity((data.len() * 8 + 5) / 6);
    let mut bitbuf: u32 = 0;
    let mut bitcnt: u32 = 0;
    for &b in data {
        bitbuf = (bitbuf << 8) | (b as u32);
        bitcnt += 8;
        while bitcnt >= 6 {
            bitcnt -= 6;
            syms.push(((bitbuf >> bitcnt) & 0x3F) as u8);
        }
    }
    if bitcnt > 0 {
        syms.push(((bitbuf << (6 - bitcnt)) & 0x3F) as u8);
    }
    syms
}

fn symbols_6bit_to_bytes(syms: &[u8], expected_bytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(expected_bytes);
    let mut bitbuf: u32 = 0;
    let mut bitcnt: u32 = 0;
    for &s in syms {
        bitbuf = (bitbuf << 6) | ((s & 0x3F) as u32);
        bitcnt += 6;
        while bitcnt >= 8 && out.len() < expected_bytes {
            bitcnt -= 8;
            out.push(((bitbuf >> bitcnt) & 0xFF) as u8);
        }
    }
    out
}

fn sync_preamble(rx: &[f64], down_conj: &[C64; M_CHIPS], up_conj: &[C64; M_CHIPS]) -> Result<usize, AcousticError> {
    if rx.len() < 7 * SAMPLES_PER_SYM {
        return Err(AcousticError::BufferTooShort);
    }
    let max_search = (rx.len().saturating_sub(45 * SAMPLES_PER_SYM)).min(180 * SAMPLES_PER_SYM);
    let mut best_score = -1.0f64;
    let mut best_pos = SAMPLES_PER_SYM;

    let mut pos = SAMPLES_PER_SYM;
    while pos < max_search {
        let bb_up = downconvert_symbol(rx, pos - SAMPLES_PER_SYM);
        let bb_d1 = downconvert_symbol(rx, pos);
        let bb_d2 = downconvert_symbol(rx, pos + SAMPLES_PER_SYM);
        let mut de_up = [C64::default(); M_CHIPS];
        let mut de_d1 = [C64::default(); M_CHIPS];
        let mut de_d2 = [C64::default(); M_CHIPS];
        for n in 0..M_CHIPS {
            de_up[n] = bb_up[n].mul(down_conj[n]);
            de_d1[n] = bb_d1[n].mul(up_conj[n]);
            de_d2[n] = bb_d2[n].mul(up_conj[n]);
        }
        let (_, r_up) = peak_and_ratio(&dft_64_mags(&de_up));
        let (_, r_d1) = peak_and_ratio(&dft_64_mags(&de_d1));
        let (_, r_d2) = peak_and_ratio(&dft_64_mags(&de_d2));
        let score = r_up * r_d1 * r_d2;
        if score > best_score {
            best_score = score;
            best_pos = pos;
        }
        pos += 160;
    }

    if best_score < 27.0 {
        return Err(AcousticError::SyncFailed);
    }

    // Fine bin-0 alignment on Up-Chirp #4 and Down-Chirp #1
    let fine_start = best_pos.saturating_sub(640).max(SAMPLES_PER_SYM);
    let fine_end = (best_pos + 640).min(rx.len() - 2 * SAMPLES_PER_SYM);
    let mut fine_best = -1.0f64;
    let mut fine_pos = best_pos;

    let mut cand = fine_start;
    while cand <= fine_end {
        let bb_up = downconvert_symbol(rx, cand - SAMPLES_PER_SYM);
        let bb_d1 = downconvert_symbol(rx, cand);
        let mut de_up = [C64::default(); M_CHIPS];
        let mut de_d1 = [C64::default(); M_CHIPS];
        for n in 0..M_CHIPS {
            de_up[n] = bb_up[n].mul(down_conj[n]);
            de_d1[n] = bb_d1[n].mul(up_conj[n]);
        }
        let s0 = dft_64_mags(&de_up)[0] * dft_64_mags(&de_d1)[0];
        if s0 > fine_best {
            fine_best = s0;
            fine_pos = cand;
        }
        cand += 10;
    }

    Ok(fine_pos + 2 * SAMPLES_PER_SYM)
}

// ============================================================================
// Public Modem API (PCM-16 48 kHz Ready for Android AudioTrack / AudioRecord)
// ============================================================================

/// Modulates a 254-byte AETHER RFC-0001 packet into 48 kHz PCM-16 ultrasonic audio (10.35 s).
pub fn encode_aether_254_pcm16(pkt254: &[u8; AETHER_FRAME_BYTES]) -> Vec<i16> {
    let gf = Gf256::new();
    let b0 = gf.rs_encode(&pkt254[..127], RS_PARITY_BYTES);
    let b1 = gf.rs_encode(&pkt254[127..], RS_PARITY_BYTES);
    let mut interleaved = vec![0u8; 286];
    for i in 0..143 {
        interleaved[2 * i] = b0[i];
        interleaved[2 * i + 1] = b1[i];
    }
    let syms = bytes_to_6bit_symbols(&interleaved);

    let mut audio = Vec::with_capacity((6 + syms.len()) * SAMPLES_PER_SYM);
    for _ in 0..4 {
        synth_chirp_f64(0, false, &mut audio);
    }
    for _ in 0..2 {
        synth_chirp_f64(0, true, &mut audio);
    }
    for s in syms {
        synth_chirp_f64(s, false, &mut audio);
    }
    audio.into_iter().map(|v| (v * 26_000.0).clamp(-32767.0, 32767.0) as i16).collect()
}

/// Demodulates a 48 kHz PCM-16 recording into a 254-byte AETHER packet (with RS FEC).
pub fn decode_aether_254_pcm16(pcm16: &[i16]) -> Result<[u8; AETHER_FRAME_BYTES], AcousticError> {
    let rx: Vec<f64> = pcm16.iter().map(|&s| (s as f64) / 32768.0).collect();
    let (down_conj, up_conj) = ref_chirps();
    let payload_start = sync_preamble(&rx, &down_conj, &up_conj)?;
    let n_syms = (286 * 8 + 5) / 6; // 382
    if payload_start + n_syms * SAMPLES_PER_SYM > rx.len() {
        return Err(AcousticError::BufferTooShort);
    }

    let mut rx_syms = Vec::with_capacity(n_syms);
    for i in 0..n_syms {
        let bb = downconvert_symbol(&rx, payload_start + i * SAMPLES_PER_SYM);
        let mut de = [C64::default(); M_CHIPS];
        for n in 0..M_CHIPS {
            de[n] = bb[n].mul(down_conj[n]);
        }
        let (sym, _) = peak_and_ratio(&dft_64_mags(&de));
        rx_syms.push(sym);
    }

    let interleaved = symbols_6bit_to_bytes(&rx_syms, 286);
    let mut b0 = Vec::with_capacity(143);
    let mut b1 = Vec::with_capacity(143);
    for i in 0..143 {
        b0.push(interleaved[2 * i]);
        b1.push(interleaved[2 * i + 1]);
    }
    let gf = Gf256::new();
    let d0 = gf.rs_decode(&b0, RS_PARITY_BYTES)?;
    let d1 = gf.rs_decode(&b1, RS_PARITY_BYTES)?;
    let mut out = [0u8; AETHER_FRAME_BYTES];
    out[..127].copy_from_slice(&d0);
    out[127..].copy_from_slice(&d1);
    Ok(out)
}

/// Modulates a 16-byte Basal SOS crisis decision frame into 48 kHz PCM-16 audio (1.31 s, RS(32,16)).
pub fn encode_basal_sos_16_pcm16(sos16: &[u8; BASAL_SOS_BYTES]) -> Vec<i16> {
    let gf = Gf256::new();
    let cw = gf.rs_encode(sos16, RS_PARITY_BYTES);
    let syms = bytes_to_6bit_symbols(&cw);
    let mut audio = Vec::with_capacity((6 + syms.len()) * SAMPLES_PER_SYM);
    for _ in 0..4 {
        synth_chirp_f64(0, false, &mut audio);
    }
    for _ in 0..2 {
        synth_chirp_f64(0, true, &mut audio);
    }
    for s in syms {
        synth_chirp_f64(s, false, &mut audio);
    }
    audio.into_iter().map(|v| (v * 26_000.0).clamp(-32767.0, 32767.0) as i16).collect()
}

/// Demodulates a 16-byte Basal SOS crisis decision frame from 48 kHz PCM-16 audio.
pub fn decode_basal_sos_16_pcm16(pcm16: &[i16]) -> Result<[u8; BASAL_SOS_BYTES], AcousticError> {
    let rx: Vec<f64> = pcm16.iter().map(|&s| (s as f64) / 32768.0).collect();
    let (down_conj, up_conj) = ref_chirps();
    let payload_start = sync_preamble(&rx, &down_conj, &up_conj)?;
    let n_syms = (32 * 8 + 5) / 6; // 43
    if payload_start + n_syms * SAMPLES_PER_SYM > rx.len() {
        return Err(AcousticError::BufferTooShort);
    }

    let mut rx_syms = Vec::with_capacity(n_syms);
    for i in 0..n_syms {
        let bb = downconvert_symbol(&rx, payload_start + i * SAMPLES_PER_SYM);
        let mut de = [C64::default(); M_CHIPS];
        for n in 0..M_CHIPS {
            de[n] = bb[n].mul(down_conj[n]);
        }
        let (sym, _) = peak_and_ratio(&dft_64_mags(&de));
        rx_syms.push(sym);
    }

    let cw = symbols_6bit_to_bytes(&rx_syms, 32);
    let gf = Gf256::new();
    let data = gf.rs_decode(&cw, RS_PARITY_BYTES)?;
    let mut out = [0u8; BASAL_SOS_BYTES];
    out.copy_from_slice(&data);
    Ok(out)
}
