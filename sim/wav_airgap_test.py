#!/usr/bin/env python3
"""
AETHER 5-Minute Real-Room Air-Gap Tester (19.5 kHz Ultrasonic CSS).
1) Generate WAV:  python3 sim/wav_airgap_test.py encode "Czesc kochanie, dziala bez neta!" out.wav
2) Play out.wav on laptop/Phone A speaker, record on Phone B (48 kHz WAV).
3) Decode WAV:    python3 sim/wav_airgap_test.py decode recorded.wav
"""
import sys, wave, struct, hashlib
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import ultrasonic_bench as ucss

def sync_preamble_full(rx):
    S = ucss.SAMPLES_PER_SYM
    M = ucss.M
    # Leave room for 2 down-chirps + 382 data symbols
    max_search = max(S + 1, len(rx) - 384 * S)
    best_s, best_p = -1.0, S
    # Fast coarse scan (step 320 samples = 6.7 ms) across arbitrary leading silence!
    for p in range(S, max_search, 320):
        _, r0 = ucss.peak_pn(ucss.dft_mags([ucss.downconv(rx, p - S)[n] * ucss.REF_DOWN[n] for n in range(M)]))
        _, r1 = ucss.peak_pn(ucss.dft_mags([ucss.downconv(rx, p)[n] * ucss.REF_UP_C[n] for n in range(M)]))
        _, r2 = ucss.peak_pn(ucss.dft_mags([ucss.downconv(rx, p + S)[n] * ucss.REF_UP_C[n] for n in range(M)]))
        sc = r0 * r1 * r2
        if sc > best_s:
            best_s, best_p = sc, p
    # Fine bin-0 alignment
    fb, fp = -1.0, best_p
    for c in range(max(S, best_p - 640), min(len(rx) - 2 * S, best_p + 641), 10):
        m_up = ucss.dft_mags([ucss.downconv(rx, c - S)[n] * ucss.REF_DOWN[n] for n in range(M)])
        m_dn = ucss.dft_mags([ucss.downconv(rx, c)[n] * ucss.REF_UP_C[n] for n in range(M)])
        s0 = m_up[0] * m_dn[0]
        if s0 > fb:
            fb, fp = s0, c
    return fp + 2 * S

def encode_text_to_wav(text: str, wav_path: str):
    raw = text.encode("utf-8")[:250]
    pkt = bytearray(254)
    pkt[0] = len(raw)
    pkt[1:1 + len(raw)] = raw
    pad = hashlib.sha256(raw).digest() * 8
    pkt[1 + len(raw):254] = pad[:253 - len(raw)]

    b0 = ucss.rs_encode(bytes(pkt[:127]), 16)
    b1 = ucss.rs_encode(bytes(pkt[127:]), 16)
    inter = bytes(v for pair in zip(b0, b1) for v in pair)
    tx = (
        [0.0] * 24000  # 0.5 s lead silence
        + sum((ucss.synth(0, False) for _ in range(4)), [])
        + sum((ucss.synth(0, True) for _ in range(2)), [])
        + sum((ucss.synth(s, False) for s in ucss.to_syms(inter)), [])
        + [0.0] * 24000
    )
    pcm = [max(-32767, min(32767, int(v * 26000.0))) for v in tx]
    with wave.open(wav_path, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(48000)
        wf.writeframes(struct.pack(f"<{len(pcm)}h", *pcm))
    print(f"[OK] Saved {wav_path} ({len(pcm)/48000:.2f} s @ 48 kHz, 18.3-20.7 kHz). Play aloud & record!")

def decode_wav_to_text(wav_path: str):
    with wave.open(wav_path, "rb") as wf:
        assert wf.getframerate() == 48000, f"Expected 48000 Hz WAV, got {wf.getframerate()}"
        nch = wf.getnchannels()
        frames = wf.readframes(wf.getnframes())
    raw_i16 = struct.unpack(f"<{len(frames)//2}h", frames)
    mono = [raw_i16[i] / 32768.0 for i in range(0, len(raw_i16), nch)]
    st = sync_preamble_full(mono)
    syms = [
        ucss.peak_pn(ucss.dft_mags([ucss.downconv(mono, st + i * ucss.SAMPLES_PER_SYM)[n] * ucss.REF_DOWN[n] for n in range(ucss.M)]))[0]
        for i in range(382)
    ]
    dec_i = ucss.from_syms(syms, 286)
    d0, e0 = ucss.rs_decode(dec_i[0::2], 16)
    d1, e1 = ucss.rs_decode(dec_i[1::2], 16)
    pkt = d0 + d1
    msg_len = pkt[0]
    text = pkt[1:1 + msg_len].decode("utf-8", errors="replace")
    print(f"[DECODED OK] RS fixed {e0 + e1} bytes | Message: {text}")
    return text

if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "encode":
        encode_text_to_wav(sys.argv[2], sys.argv[3])
    elif len(sys.argv) >= 3 and sys.argv[1] == "decode":
        decode_wav_to_text(sys.argv[2])
    else:
        print("Usage:\n  python3 sim/wav_airgap_test.py encode 'Twoja wiadomosc' out.wav\n  python3 sim/wav_airgap_test.py decode out.wav")
