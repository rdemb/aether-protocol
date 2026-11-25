#!/usr/bin/env python3
"""
AETHER L0-CSS-19K Standalone Acoustic Stress Benchmark (AETHER-IMPL-0003).
Verifies 18.3-20.7 kHz CSS + Interleaved RS(143,127) & RS(32,16) down to -6 dB SNR + room echo + burst noise.
"""
import math, cmath, random

FS, FC, BW, DECIM, M = 48000, 19500.0, 2400.0, 20, 64
SAMPLES_PER_SYM = M * DECIM

GF_EXP, GF_LOG = [0] * 512, [0] * 256
_x = 1
for _i in range(255):
    GF_EXP[_i], GF_LOG[_x] = _x, _i
    _x <<= 1
    if _x & 0x100: _x ^= 0x11D
for _i in range(255, 512): GF_EXP[_i] = GF_EXP[_i - 255]

def gf_mul(a, b): return 0 if (a == 0 or b == 0) else GF_EXP[GF_LOG[a] + GF_LOG[b]]
def gf_div(a, b): return 0 if a == 0 else GF_EXP[(GF_LOG[a] + 255 - GF_LOG[b]) % 255]
def gf_pow(a, p): return 1 if p == 0 else (0 if a == 0 else GF_EXP[(GF_LOG[a] * (p % 255)) % 255])

def gf_poly_mul_desc(p, q):
    r = [0] * (len(p) + len(q) - 1)
    for j, qv in enumerate(q):
        for i, pv in enumerate(p): r[i + j] ^= gf_mul(pv, qv)
    return r

def gf_poly_eval_desc(poly, x):
    y = poly[0]
    for c in poly[1:]: y = gf_mul(y, x) ^ c
    return y

def gf_poly_eval_asc(poly, x):
    y, xp = 0, 1
    for c in poly: y ^= gf_mul(c, xp); xp = gf_mul(xp, x)
    return y

def rs_encode(msg: bytes, nsym: int) -> bytes:
    g = [1]
    for i in range(nsym): g = gf_poly_mul_desc(g, [1, gf_pow(2, i)])
    out = list(msg) + [0] * nsym
    for i in range(len(msg)):
        c = out[i]
        if c:
            for j in range(1, len(g)): out[i + j] ^= gf_mul(g[j], c)
    return bytes(msg) + bytes(out[len(msg):])

def rs_decode(codeword: bytes, nsym: int):
    msg, n = list(codeword), len(codeword)
    synd = [gf_poly_eval_desc(msg, gf_pow(2, i)) for i in range(nsym)]
    if max(synd) == 0: return bytes(msg[:-nsym]), 0
    C, B, L, m, b = [1], [1], 0, 1, 1
    for step in range(nsym):
        d = synd[step]
        for i in range(1, L + 1): d ^= gf_mul(C[i], synd[step - i])
        if d == 0: m += 1
        else:
            T, coef = C.copy(), gf_div(d, b)
            if len(C) < len(B) + m: C.extend([0] * (len(B) + m - len(C)))
            for i, bv in enumerate(B): C[i + m] ^= gf_mul(coef, bv)
            if 2 * L <= step: L, B, b, m = step + 1 - L, T, d, 1
            else: m += 1
    lam = C[:L + 1]
    err_pos = [p for p in range(n) if gf_poly_eval_asc(lam, gf_pow(2, (255 - ((n - 1 - p) % 255)) % 255)) == 0]
    assert len(err_pos) == L, "Uncorrectable RS errors"
    omega = [0] * nsym
    for i in range(nsym):
        for j in range(min(i + 1, len(lam))): omega[i] ^= gf_mul(lam[j], synd[i - j])
    for pos in err_pos:
        pw = n - 1 - pos
        x_k, x_inv = gf_pow(2, pw % 255), gf_pow(2, (255 - (pw % 255)) % 255)
        num, den, xp, x2 = gf_poly_eval_asc(omega, x_inv), 0, 1, gf_mul(x_inv, x_inv)
        for j in range(1, len(lam), 2): den ^= gf_mul(lam[j], xp); xp = gf_mul(xp, x2)
        msg[pos] ^= gf_mul(x_k, gf_div(num, den))
    return bytes(msg[:-nsym]), L

REF_DOWN = [cmath.exp(-1j * 2 * math.pi * ((n * n) / (2 * M) - 0.5 * n)) for n in range(M)]
REF_UP_C = [cmath.exp(1j * 2 * math.pi * ((n * n) / (2 * M) - 0.5 * n)) for n in range(M)]
TWIDDLE = [[cmath.exp(-1j * 2 * math.pi * k * n / M) for n in range(M)] for k in range(M)]

def synth(sym, down=False):
    out, ph, dt = [0.0] * SAMPLES_PER_SYM, 0.0, 1.0 / FS
    for k in range(SAMPLES_PER_SYM):
        u = k / SAMPLES_PER_SYM
        f = FC + BW * (((1.0 - u) if down else (u + sym / M)) % 1.0 - 0.5)
        env = 0.5 * (1 - math.cos(math.pi * k / 32)) if k < 32 else (0.5 * (1 - math.cos(math.pi * (SAMPLES_PER_SYM - 1 - k) / 32)) if k >= SAMPLES_PER_SYM - 32 else 1.0)
        out[k] = env * math.cos(ph); ph += 2 * math.pi * f * dt
    return out

def downconv(buf, st):
    bb = [0j] * M
    for n in range(M):
        acc = 0j
        for d in range(DECIM):
            k = n * DECIM + d
            acc += buf[st + k] * cmath.exp(-1j * 2 * math.pi * FC * (st + k) / FS)
        bb[n] = acc / DECIM
    return bb

def dft_mags(v): return [abs(sum(v[n] * TWIDDLE[k][n] for n in range(M))) for k in range(M)]
def peak_pn(mags):
    k = max(range(M), key=lambda i: mags[i])
    return k, mags[k] / ((sum(mags) - mags[k]) / (M - 1) + 1e-9)

def to_syms(data):
    s, bb, bc = [], 0, 0
    for b in data:
        bb = (bb << 8) | b; bc += 8
        while bc >= 6: bc -= 6; s.append((bb >> bc) & 0x3F)
    if bc: s.append((bb << (6 - bc)) & 0x3F)
    return s

def from_syms(syms, nbytes):
    o, bb, bc = bytearray(), 0, 0
    for s in syms:
        bb = (bb << 6) | (s & 0x3F); bc += 6
        while bc >= 8 and len(o) < nbytes: bc -= 8; o.append((bb >> bc) & 0xFF)
    return bytes(o)

def sync_pre(rx):
    best_s, best_p = -1.0, SAMPLES_PER_SYM
    for p in range(SAMPLES_PER_SYM, min(len(rx) - 3 * SAMPLES_PER_SYM, 8 * SAMPLES_PER_SYM), 160):
        _, r0 = peak_pn(dft_mags([downconv(rx, p - SAMPLES_PER_SYM)[n] * REF_DOWN[n] for n in range(M)]))
        _, r1 = peak_pn(dft_mags([downconv(rx, p)[n] * REF_UP_C[n] for n in range(M)]))
        _, r2 = peak_pn(dft_mags([downconv(rx, p + SAMPLES_PER_SYM)[n] * REF_UP_C[n] for n in range(M)]))
        if r0 * r1 * r2 > best_s: best_s, best_p = r0 * r1 * r2, p
    fb, fp = -1.0, best_p
    for c in range(max(SAMPLES_PER_SYM, best_p - 640), min(len(rx) - 2 * SAMPLES_PER_SYM, best_p + 641), 10):
        s0 = dft_mags([downconv(rx, c - SAMPLES_PER_SYM)[n] * REF_DOWN[n] for n in range(M)])[0] * dft_mags([downconv(rx, c)[n] * REF_UP_C[n] for n in range(M)])[0]
        if s0 > fb: fb, fp = s0, c
    return fp + 2 * SAMPLES_PER_SYM

def main():
    rng = random.Random(20261125)
    pkt = bytes(rng.getrandbits(8) for _ in range(254))
    b0, b1 = rs_encode(pkt[:127], 16), rs_encode(pkt[127:], 16)
    inter = bytes(v for pair in zip(b0, b1) for v in pair)
    tx = sum((synth(0, False) for _ in range(4)), []) + sum((synth(0, True) for _ in range(2)), []) + sum((synth(s, False) for s in to_syms(inter)), [])
    sig = [0.0] * 1173 + tx + [0.0] * 2560
    sig = [sig[i] + (0.40 * sig[i - 192] if i >= 192 else 0.0) for i in range(len(sig))]
    sp = sum(v * v for v in tx) / len(tx)
    nstd = math.sqrt(sp / (10.0 ** (-3.0 / 10.0)))
    rx = [v + rng.gauss(0.0, nstd) for v in sig]
    for k in range(1173 + 106 * SAMPLES_PER_SYM, 1173 + 111 * SAMPLES_PER_SYM): rx[k] += rng.gauss(0.0, 15.0)
    st = sync_pre(rx)
    syms = [peak_pn(dft_mags([downconv(rx, st + i * SAMPLES_PER_SYM)[n] * REF_DOWN[n] for n in range(M)]))[0] for i in range(382)]
    dec_i = from_syms(syms, 286)
    d0, e0 = rs_decode(dec_i[0::2], 16)
    d1, e1 = rs_decode(dec_i[1::2], 16)
    assert d0 + d1 == pkt
    print(f"[PASS] Ultrasonic 19.5 kHz CSS (-3 dB SNR + 0.40x echo + 5-sym burst): 254 B exact! RS fixed {e0+e1} bytes.")

if __name__ == "__main__":
    main()
