//! Normative Compliance Test Suite for AETHER RFC-0001 and RFC-0002.
//! Run with: `cargo test --release --test rfc_compliance -- --nocapture`

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use x25519_dalek::{PublicKey, StaticSecret};

use aether_core::decay::{resolve_gnss_epoch, should_relay_geometric};
use aether_core::dtn::{BarterSession, DtnNode, IngestDecision};
use aether_core::elligator::{elligator2_decode, generate_elligator2_ephemeral};
use aether_core::minisketch::Minisketch;
use aether_core::pow::{seal_packet_with_pow, verify_packet_pow, POW_DIFFICULTY_MIN};
use aether_core::pqxdh::{
    fragment_init_payload_raptorq, generate_ml_kem_768, initiator_pqxdh,
    reconstruct_init_payload_raptorq, responder_pqxdh, INIT_PAYLOAD_SIZE,
};
use aether_core::rans_slm::{
    isqrt_u64, rans_encode_sequence, CompressionError, RansDecoder, RansDistribution, RANS_SCALE,
    VOCAB_SIZE,
};
use aether_core::tag::{derive_session_tag, TagChainState};
use aether_core::wire::{CtrlByte, InnerPlaintext, OuterPacket, PacketClass, PACKET_SIZE};

#[test]
fn test_01_rfc0001_packet_whitenoise_statistics() {
    let mut rng = StdRng::seed_from_u64(0xAE74_E201);
    let n_packets = 200;
    let mut ones: i64 = 0;
    let mut total_bits: i64 = 0;
    let mut runs: i64 = 1;
    let mut prev_bit: Option<u8> = None;
    let mut msb_254_255_hist = [0u32; 4];

    for i in 0..n_packets {
        let mut raw = [0u8; PACKET_SIZE];
        rng.fill_bytes(&mut raw);
        let (_, _, rep) = generate_elligator2_ephemeral(&mut rng);
        raw[8..40].copy_from_slice(&rep);
        msb_254_255_hist[((raw[39] >> 6) & 0b11) as usize] += 1;

        let ctrl = CtrlByte {
            proto_ver: 0,
            packet_class: PacketClass::DataRatchet,
            decay_class: 0x8,
        };
        seal_packet_with_pow(&mut raw, ctrl.to_u8(), (i & 0xFF) as u8, 10, rng.next_u64());

        for &byte in raw.iter() {
            for bit_idx in 0..8 {
                let b = (byte >> bit_idx) & 1;
                ones += b as i64;
                total_bits += 1;
                if let Some(p) = prev_bit {
                    if b != p {
                        runs += 1;
                    }
                }
                prev_bit = Some(b);
            }
        }
    }

    let s_n = (2 * ones - total_bits).abs() as f64;
    let s_obs = s_n / (total_bits as f64).sqrt();
    assert!(s_obs < 2.576, "NIST Frequency Test failed: S_obs = {s_obs}");

    let pi = (ones as f64) / (total_bits as f64);
    let expected_runs = 2.0 * (total_bits as f64) * pi * (1.0 - pi);
    let std_runs = (2.0 * (total_bits as f64)).sqrt() * pi * (1.0 - pi) * 2.0;
    let z_runs = ((runs as f64) - expected_runs).abs() / std_runs;
    assert!(z_runs < 3.0, "NIST Runs Test failed: z = {z_runs}");

    for (bucket, &count) in msb_254_255_hist.iter().enumerate() {
        assert!(count > 25, "Elligator-2 MSB bits 254..255 biased (bucket {bucket}: {count})");
    }
}

#[test]
fn test_02_rfc0001_elligator2_roundtrip_and_pqxdh_raptorq() {
    let mut rng = StdRng::seed_from_u64(0xAE74_E209);

    // 100 Elligator-2 round-trips
    for _ in 0..100 {
        let (_, pk, rep) = generate_elligator2_ephemeral(&mut rng);
        let decoded = elligator2_decode(&rep);
        assert_eq!(decoded.as_bytes(), pk.as_bytes(), "Elligator-2 round-trip mismatch");
    }

    // Hybrid X25519 + ML-KEM-768 PQXDH handshake
    let mut s_ik_a = [0u8; 32];
    let mut s_ik_b = [0u8; 32];
    let mut s_spk_b = [0u8; 32];
    rng.fill_bytes(&mut s_ik_a);
    rng.fill_bytes(&mut s_ik_b);
    rng.fill_bytes(&mut s_spk_b);

    let ik_a = StaticSecret::from(s_ik_a);
    let ik_b = StaticSecret::from(s_ik_b);
    let spk_b = StaticSecret::from(s_spk_b);
    let (ek_a, ek_a_pub, ek_a_rep) = generate_elligator2_ephemeral(&mut rng);
    let (pq_dk, pq_ek, ek_len) = generate_ml_kem_768(&mut rng);
    assert_eq!(ek_len, 1184, "ML-KEM-768 encapsulation key must be 1184 B");

    let (alice_keys, ct_pq) = initiator_pqxdh(
        &ik_a,
        &ek_a,
        &PublicKey::from(&ik_b),
        &PublicKey::from(&spk_b),
        &pq_ek,
        &mut rng,
    );
    assert_eq!(ct_pq.as_slice().len(), 1088, "ML-KEM-768 ciphertext must be 1088 B");

    // Tunnel 1152-byte InitPayload via RaptorQ (K=7 + 3 repair, drop first 3 packets!)
    let mut init_payload = [0u8; INIT_PAYLOAD_SIZE];
    init_payload[44..44 + 1088].copy_from_slice(ct_pq.as_slice());
    let (oti, fragments) = fragment_init_payload_raptorq(&init_payload, 3);
    assert!(fragments.len() >= 10);
    // Drop first 3 packets to simulate lossy Kineto-DTN paths
    let received_subset = &fragments[3..];
    let recovered = reconstruct_init_payload_raptorq(oti, received_subset)
        .expect("RaptorQ failed to reconstruct InitPayload after 30% loss");
    assert_eq!(recovered, init_payload);

    let decoded_ek_a = elligator2_decode(&ek_a_rep);
    assert_eq!(decoded_ek_a.as_bytes(), ek_a_pub.as_bytes());
    let bob_keys = responder_pqxdh(
        &ik_b,
        &spk_b,
        &pq_dk,
        &PublicKey::from(&ik_a),
        &decoded_ek_a,
        &ct_pq,
    );
    assert_eq!(alice_keys.sk_root, bob_keys.sk_root);
    assert_eq!(alice_keys.tag_root_key, bob_keys.tag_root_key);
}

#[test]
fn test_03_rfc0001_geometric_ttl_chi_square() {
    let mut rng = StdRng::seed_from_u64(0xAE74_E202);
    let trials = 50_000usize;
    let decay_class = 0x8u8;
    let p: f64 = (0xE666u32 as f64) / 65536.0;
    let q: f64 = 1.0 - p;

    let mut observed = [0u64; 10];
    for _ in 0..trials {
        let mut hops = 1usize;
        while hops < 10 && should_relay_geometric(decay_class, &mut rng) {
            hops += 1;
        }
        observed[hops - 1] += 1;
    }

    let mut chi2 = 0.0;
    for k in 1..=9 {
        let prob = p.powi((k - 1) as i32) * q;
        let expected = (trials as f64) * prob;
        let diff = (observed[k - 1] as f64) - expected;
        chi2 += (diff * diff) / expected;
    }
    let expected_tail = (trials as f64) * p.powi(9);
    let diff_tail = (observed[9] as f64) - expected_tail;
    chi2 += (diff_tail * diff_tail) / expected_tail;

    assert!(chi2 < 21.666, "Geometric TTL chi-square failed: chi2 = {chi2:.3}");
}

#[test]
fn test_04_rfc0001_pow_and_tamper_resistance() {
    let mut rng = StdRng::seed_from_u64(0xAE74_E203);
    let mut raw = [0u8; PACKET_SIZE];
    rng.fill_bytes(&mut raw);

    let ctrl = CtrlByte {
        proto_ver: 0,
        packet_class: PacketClass::DataRatchet,
        decay_class: 0x8,
    };
    let epoch_lsb = 0xABu8;
    seal_packet_with_pow(&mut raw, ctrl.to_u8(), epoch_lsb, POW_DIFFICULTY_MIN, 0);

    let pkt = OuterPacket::from_slice(&raw).unwrap();
    let (decoded_ctrl, decoded_ep) = pkt.unmask_ctrl_and_epoch().unwrap();
    assert_eq!(decoded_ctrl, ctrl);
    assert_eq!(decoded_ep, epoch_lsb);
    assert!(verify_packet_pow(&pkt, 50).unwrap() >= POW_DIFFICULTY_MIN);

    let mut tampered = raw;
    tampered[120] ^= 0x01;
    assert!(verify_packet_pow(&OuterPacket::from_slice(&tampered).unwrap(), 50).is_err());
}

#[test]
fn test_05_rfc0001_minisketch_gnss_barter_fsm() {
    let mut rng = StdRng::seed_from_u64(0xAE74_E205);

    // Minisketch GF(2^64)
    let mut sa = Minisketch::new();
    let mut sb = Minisketch::new();
    sa.add(0x1111_2222_3333_4444);
    sb.add(0x1111_2222_3333_4444);
    sa.add(0xAAAA_BBBB_CCCC_DDDD);
    sb.add(0x1234_5678_9ABC_DEF0);
    let bytes_a = sa.to_bytes();
    assert_eq!(bytes_a.len(), 176);
    assert_eq!(Minisketch::from_bytes(&bytes_a), sa);
    let mut diff = sa.clone();
    diff.merge(&sb);
    let mut exp = Minisketch::new();
    exp.add(0xAAAA_BBBB_CCCC_DDDD);
    exp.add(0x1234_5678_9ABC_DEF0);
    assert_eq!(diff, exp);

    // GNSS wrap-around
    assert_eq!(resolve_gnss_epoch(512, 0xFF), Some(511));
    assert_eq!(resolve_gnss_epoch(512, 0x01), Some(513));
    assert_eq!(resolve_gnss_epoch(512, 0x02), None);
    assert_eq!(resolve_gnss_epoch(512, 184), Some(440));
    assert_eq!(resolve_gnss_epoch(512, 183), None);

    // Barter Tit-for-Tat
    let mut barter = BarterSession::new();
    barter.record_sent();
    barter.record_sent();
    assert!(!barter.can_send_next());
    barter.record_valid_received();
    assert!(barter.can_send_next());

    // O(1) Tag delivery & deduplication
    let mut node = DtnNode::new(64);
    let mut chain = TagChainState {
        contact_id: 7,
        chain_tag_key: [0x42u8; 32],
        next_seq: 0,
    };
    let (msg_tag_key, seq) = chain.advance();
    let current_epoch = 490_000u64;
    let tag = derive_session_tag(&msg_tag_key, current_epoch);
    node.tag_index.insert(tag, 7, seq);

    let mut raw = [0u8; PACKET_SIZE];
    rng.fill_bytes(&mut raw);
    raw[0..8].copy_from_slice(&tag);
    let ctrl = CtrlByte {
        proto_ver: 0,
        packet_class: PacketClass::DataRatchet,
        decay_class: 0x8,
    };
    seal_packet_with_pow(&mut raw, ctrl.to_u8(), (current_epoch & 0xFF) as u8, POW_DIFFICULTY_MIN, 0);

    assert_eq!(
        node.ingest_packet(&raw, current_epoch, &mut rng),
        IngestDecision::DeliveredToLocalContact {
            contact_id: 7,
            seq: 0,
            epoch_hour: current_epoch,
        }
    );
    assert_eq!(
        node.ingest_packet(&raw, current_epoch, &mut rng),
        IngestDecision::DuplicateIgnored
    );
}

#[test]
fn test_06_rfc0002_deterministic_rans_and_fixed_point() {
    let mut rng = StdRng::seed_from_u64(0xAE74_E206);

    for &v in &[0u64, 1, 2, 3, 4, 15, 16, 17, 1_000_000, u64::MAX] {
        let r = isqrt_u64(v);
        assert!(r.checked_mul(r).map_or(false, |sq| sq <= v));
        if let Some(r1) = r.checked_add(1) {
            if let Some(sq1) = r1.checked_mul(r1) {
                assert!(sq1 > v);
            }
        }
    }

    for logits in &[[0i32; VOCAB_SIZE], [i32::MIN / 2; VOCAB_SIZE], [i32::MAX / 2; VOCAB_SIZE]] {
        let dist = RansDistribution::from_logits_q16(logits);
        let sum: u32 = dist.freq.iter().map(|&f| f as u32).sum();
        assert_eq!(sum, RANS_SCALE);
        assert!(dist.freq.iter().all(|&f| f >= 1));
    }

    let mut dists = Vec::with_capacity(256);
    let mut tokens = Vec::with_capacity(256);
    let mut enc_pairs = Vec::with_capacity(256);

    for step in 0..256u32 {
        let mut logits = [-(8 << 16); VOCAB_SIZE];
        let hot = ((step * 37) as usize) % VOCAB_SIZE;
        logits[hot] = 10 << 16;
        logits[(hot + 1) % VOCAB_SIZE] = 7 << 16;
        logits[(hot + 2) % VOCAB_SIZE] = 4 << 16;

        let dist = RansDistribution::from_logits_q16(&logits);
        let tok = if step % 5 == 0 {
            (rng.next_u32() as usize % VOCAB_SIZE) as u16
        } else {
            hot as u16
        };
        enc_pairs.push((dist.cdf[tok as usize], dist.freq[tok as usize]));
        tokens.push(tok);
        dists.push(dist);
    }

    let (final_state, stream) = rans_encode_sequence(&enc_pairs);
    let mut dec = RansDecoder::new(final_state, &stream).unwrap();
    let mut decoded = Vec::with_capacity(256);
    for dist in &dists {
        decoded.push(dec.decode_next(dist).unwrap());
    }
    dec.finish().unwrap();
    assert_eq!(decoded, tokens);

    // InnerPlaintext round-trip
    let inner = InnerPlaintext {
        codec_id: 0b10,
        frag_mode: 0b00,
        has_htlc: false,
        priority: true,
        seq_or_obj_id: 42,
        pn_or_esi: 10,
        payload: stream[..stream.len().min(182)].to_vec(),
    };
    let enc_190 = inner.encode(&mut rng).unwrap();
    assert_eq!(InnerPlaintext::decode(&enc_190).unwrap(), inner);

    // Tamper check
    if !stream.is_empty() {
        let mut bad = stream.clone();
        bad[0] ^= 0x80;
        let mut bad_dec = RansDecoder::new(final_state, &bad).unwrap();
        let mut caught = false;
        for (i, dist) in dists.iter().enumerate() {
            match bad_dec.decode_next(dist) {
                Ok(t) if t != tokens[i] => caught = true,
                Err(_) => {
                    caught = true;
                    break;
                }
                _ => {}
            }
        }
        if !caught {
            assert_eq!(bad_dec.finish(), Err(CompressionError::CorruptedStream));
        }
    }
}

#[test]
fn test_07_phase2_ultrasonic_css_modem() {
    use aether_core::ultrasonic_css::{
        decode_aether_254_pcm16, decode_basal_sos_16_pcm16, encode_aether_254_pcm16,
        encode_basal_sos_16_pcm16, SAMPLES_PER_SYM,
    };

    let mut rng = StdRng::seed_from_u64(0xAE74_E207);

    // 1. 16-byte Basal SOS crisis packet with arbitrary leading offset + burst corruption
    let mut sos = [0u8; 16];
    rng.fill_bytes(&mut sos);
    let sos_pcm = encode_basal_sos_16_pcm16(&sos);
    let mut rx_sos = vec![0i16; 731];
    rx_sos.extend_from_slice(&sos_pcm);
    rx_sos.extend_from_slice(&vec![0i16; 2560]);
    // Inject 2-symbol acoustic impulse burst
    let b_start = 731 + 6 * SAMPLES_PER_SYM + 8 * SAMPLES_PER_SYM;
    for k in b_start..b_start + 2 * SAMPLES_PER_SYM {
        rx_sos[k] = (rng.next_u32() as i16).saturating_div(2);
    }
    let decoded_sos = decode_basal_sos_16_pcm16(&rx_sos).expect("Basal SOS ultrasonic decode failed");
    assert_eq!(decoded_sos, sos);

    // 2. Full 254-byte AETHER RFC-0001 packet with multipath echo & non-aligned start
    let mut pkt = [0u8; PACKET_SIZE];
    rng.fill_bytes(&mut pkt);
    let pcm = encode_aether_254_pcm16(&pkt);
    let mut rx = vec![0i16; 915];
    rx.extend_from_slice(&pcm);
    rx.extend_from_slice(&vec![0i16; 2560]);
    // 4 ms room reflection (0.35x)
    let mut echoed = rx.clone();
    for i in 192..rx.len() {
        let v = (rx[i] as i32) + ((rx[i - 192] as i32) * 35) / 100;
        echoed[i] = v.clamp(-32767, 32767) as i16;
    }
    let decoded_pkt = decode_aether_254_pcm16(&echoed).expect("254 B ultrasonic decode failed");
    assert_eq!(decoded_pkt, pkt);
}

#[test]
fn test_08_v04_e2e_chat_and_courier_relay() {
    use aether_core::messenger::{AetherMessenger, ReceivedEvent};

    let mut rng = StdRng::seed_from_u64(0xAE74_E400);
    let epoch = 498_500u64;

    // Phone A (Husband), Phone B (Wife), Phone C (Stranger Courier with NO keys!)
    let mut phone_a = AetherMessenger::new(64);
    let mut phone_b = AetherMessenger::new(64);
    let mut courier_c = AetherMessenger::new(64);

    phone_a.pair_contact(1, "Żona", "AETHER-NASZ-KOD-2026", true, epoch);
    phone_b.pair_contact(1, "Mąż", "AETHER-NASZ-KOD-2026", false, epoch);

    // 1. Phone A composes encrypted 254 B message
    let msg_text = "Cześć! Działa całkowicie bez internetu i bez karty SIM!";
    let pkt = phone_a
        .compose_message_packet(1, msg_text, 0x0F, epoch, &mut rng)
        .expect("compose failed");
    assert_eq!(pkt.len(), PACKET_SIZE);

    // 2. Courier C walks past A (cannot decrypt, buffers blindly for relay!)
    let c_ev = courier_c.receive_packet(&pkt, epoch, &mut rng);
    match c_ev {
        ReceivedEvent::BufferedForRelay { .. } => {}
        other => panic!("Courier should buffer packet blindly, got {:?}", other),
    }

    // 3. Courier C walks 2 km later past Phone B and re-broadcasts from buffer
    let relayed_pkt = courier_c
        .next_relay_packet(epoch + 2)
        .expect("Courier must return buffered packet");
    assert_eq!(relayed_pkt, pkt);

    // 4. Phone B receives relayed packet 2 hours later and decrypts bit-exact UTF-8!
    let b_ev = phone_b.receive_packet(&relayed_pkt, epoch + 2, &mut rng);
    match b_ev {
        ReceivedEvent::DecryptedMessage { text, sender_name, .. } => {
            assert_eq!(text, msg_text);
            assert_eq!(sender_name, "Mąż");
        }
        other => panic!("Phone B failed to decrypt relayed message: {:?}", other),
    }
}
