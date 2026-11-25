//! End-to-End Encrypted Off-Grid Messaging Session Layer (AETHER v0.4.0).
//!
//! Binds RFC-0001 primitives into a complete, ready-to-chat API:
//! - Instant offline pairing via shared secret passphrase or X25519/PQXDH root key
//! - Directional key separation (Alice->Bob vs Bob->Alice) to prevent reflection
//! - ChaCha20-Poly1305 AEAD over 190-byte padded InnerPlaintext
//! - Rotating 8-byte GNSS oblivious tags with O(1) lookup across a 73-hour DTN window
//! - Elligator-2 (+2 MSB) ephemeral key obfuscation & asymmetric BLAKE3-PoW (D=18)

use std::collections::HashMap;
use blake3::Hasher;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::{CryptoRngCore, RngCore};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::decay::resolve_gnss_epoch;
use crate::dtn::{DtnNode, IngestDecision};
use crate::elligator::generate_elligator2_ephemeral;
use crate::pow::{seal_packet_with_pow, verify_packet_pow, POW_DIFFICULTY_MIN};
use crate::tag::{derive_session_tag, TagChainState};
use crate::wire::{
    CtrlByte, InnerPlaintext, OuterPacket, PacketClass, INNER_PLAINTEXT_SIZE, MAX_INNER_PAYLOAD,
    PACKET_SIZE,
};

#[derive(Debug, Error)]
pub enum MessengerError {
    #[error("Unknown contact ID")]
    UnknownContact,
    #[error("Message too long for atomic 254 B frame (> 182 UTF-8 bytes)")]
    MessageTooLong,
    #[error("AEAD encryption/decryption failed")]
    CryptoFailure,
    #[error("Wire encoding error")]
    WireFailure,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PeerSession {
    pub contact_id: u32,
    pub display_name: String,
    pub tx_enc_key: [u8; 32],
    pub rx_enc_key: [u8; 32],
    pub tx_tag_chain: TagChainState,
    pub rx_tag_chain: TagChainState,
}

/// Derives directional TX/RX encryption and oblivious tag keys from a shared secret
/// (either a PQXDH `SK_root` or an offline pairing code).
/// `is_initiator = true` on Phone A and `false` on Phone B prevents key/nonce reuse.
pub fn derive_paired_session(
    contact_id: u32,
    display_name: &str,
    shared_secret_passphrase: &str,
    is_initiator: bool,
) -> PeerSession {
    // Stretch passphrase deterministically with BLAKE3 KDF domain separation
    let mut master_h = Hasher::new();
    master_h.update(b"AETHER_PAIRING_MASTER_v04");
    master_h.update(shared_secret_passphrase.trim().as_bytes());
    let master = *master_h.finalize().as_bytes();

    let key_a_to_b = *blake3::keyed_hash(&master, b"AETHER_ENC_A2B_v1").as_bytes();
    let key_b_to_a = *blake3::keyed_hash(&master, b"AETHER_ENC_B2A_v1").as_bytes();
    let tag_a_to_b = *blake3::keyed_hash(&master, b"AETHER_TAG_A2B_v1").as_bytes();
    let tag_b_to_a = *blake3::keyed_hash(&master, b"AETHER_TAG_B2A_v1").as_bytes();

    let (tx_enc_key, rx_enc_key, tx_tag_key, rx_tag_key) = if is_initiator {
        (key_a_to_b, key_b_to_a, tag_a_to_b, tag_b_to_a)
    } else {
        (key_b_to_a, key_a_to_b, tag_b_to_a, tag_a_to_b)
    };

    PeerSession {
        contact_id,
        display_name: display_name.to_string(),
        tx_enc_key,
        rx_enc_key,
        tx_tag_chain: TagChainState {
            contact_id,
            chain_tag_key: tx_tag_key,
            next_seq: 0,
        },
        rx_tag_chain: TagChainState {
            contact_id,
            chain_tag_key: rx_tag_key,
            next_seq: 0,
        },
    }
}

fn derive_aead_key_nonce(base_key: &[u8; 32], ephemeral_rep: &[u8; 32], epoch_hour: u64) -> ([u8; 32], [u8; 12]) {
    let mut hk = Hasher::new_keyed(base_key);
    hk.update(b"AETHER_MSG_KEY_v1");
    hk.update(ephemeral_rep);
    hk.update(&epoch_hour.to_be_bytes());
    let k = *hk.finalize().as_bytes();

    let mut hn = Hasher::new_keyed(base_key);
    hn.update(b"AETHER_MSG_NONCE_v1");
    hn.update(ephemeral_rep);
    hn.update(&epoch_hour.to_be_bytes());
    let n_full = hn.finalize();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&n_full.as_bytes()[0..12]);
    (k, nonce)
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReceivedEvent {
    DecryptedMessage {
        contact_id: u32,
        sender_name: String,
        seq: u32,
        text: String,
        epoch_hour: u64,
    },
    BufferedForRelay {
        sid: u64,
        pow_bits: u8,
    },
    DuplicateIgnored,
    DroppedGeometricDecay,
    Rejected {
        reason: &'static str,
    },
}

/// Complete high-level off-grid messenger engine combining E2E chat + DTN courier relay.
pub struct AetherMessenger {
    pub dtn: DtnNode,
    pub sessions: HashMap<u32, PeerSession>,
    relay_cursor: usize,
}

impl AetherMessenger {
    pub fn new(max_buffer_packets: usize) -> Self {
        Self {
            dtn: DtnNode::new(max_buffer_packets),
            sessions: HashMap::new(),
            relay_cursor: 0,
        }
    }

    /// Pairs a contact using a shared passphrase (e.g. spoken in person or scanned via QR)
    /// and precomputes O(1) oblivious tags for the next 64 messages across [-4h, +1h] GNSS epochs.
    pub fn pair_contact(
        &mut self,
        contact_id: u32,
        display_name: &str,
        passphrase: &str,
        is_initiator: bool,
        current_epoch_hour: u64,
    ) {
        let session = derive_paired_session(contact_id, display_name, passphrase, is_initiator);
        self.precompute_rx_tags(&session, current_epoch_hour, 64);
        self.sessions.insert(contact_id, session);
    }

    /// Precomputes O(1) lookup tags so incoming frames decrypt immediately even after DTN delays.
    pub fn precompute_rx_tags(&mut self, session: &PeerSession, current_epoch_hour: u64, lookahead: usize) {
        let mut chain = session.rx_tag_chain.clone();
        for _ in 0..lookahead {
            let (msg_tag_key, seq) = chain.advance();
            // Cover [-24h .. +1h] hourly epochs (26 hours of DTN transit tolerance in RAM)
            let start_ep = current_epoch_hour.saturating_sub(24);
            let end_ep = current_epoch_hour.saturating_add(1);
            for ep in start_ep..=end_ep {
                let tag = derive_session_tag(&msg_tag_key, ep);
                self.dtn.tag_index.insert(tag, session.contact_id, seq);
            }
        }
    }

    /// Encrypts a UTF-8 text message into a valid 254-byte white-noise RFC-0001 packet
    /// (Elligator-2 + ChaCha20-Poly1305 + GNSS Oblivious Tag + BLAKE3-PoW D=18).
    pub fn compose_message_packet(
        &mut self,
        contact_id: u32,
        text: &str,
        decay_class: u8,
        current_epoch_hour: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; PACKET_SIZE], MessengerError> {
        let payload_bytes = text.as_bytes();
        if payload_bytes.len() > MAX_INNER_PAYLOAD {
            return Err(MessengerError::MessageTooLong);
        }

        let session = self
            .sessions
            .get_mut(&contact_id)
            .ok_or(MessengerError::UnknownContact)?;

        let (msg_tag_key, seq) = session.tx_tag_chain.advance();
        let oblivious_tag = derive_session_tag(&msg_tag_key, current_epoch_hour);
        let (_, _, ephemeral_rep) = generate_elligator2_ephemeral(rng);

        let inner = InnerPlaintext {
            codec_id: 0b00, // UTF-8 atomic (upgrades seamlessly to 0b10 when SLM weights attached)
            frag_mode: 0b00,
            has_htlc: false,
            priority: decay_class >= 0x0C,
            seq_or_obj_id: seq,
            pn_or_esi: 0,
            payload: payload_bytes.to_vec(),
        };
        let mut inner_buf = inner.encode(rng).map_err(|_| MessengerError::WireFailure)?;

        let ctrl = CtrlByte {
            proto_ver: 0,
            packet_class: PacketClass::DataRatchet,
            decay_class: decay_class & 0x0F,
        };
        let ctrl_plain = ctrl.to_u8();
        let epoch_lsb_plain = (current_epoch_hour & 0xFF) as u8;

        let mut raw = [0u8; PACKET_SIZE];
        raw[0..8].copy_from_slice(&oblivious_tag);
        raw[8..40].copy_from_slice(&ephemeral_rep);

        // Build 42-byte AAD_core = tag[0..8] || rep[8..40] || ctrl_plain || epoch_lsb_plain
        let mut aad = [0u8; 42];
        aad[0..40].copy_from_slice(&raw[0..40]);
        aad[40] = ctrl_plain;
        aad[41] = epoch_lsb_plain;

        let (mut aead_k, aead_n) = derive_aead_key_nonce(&session.tx_enc_key, &ephemeral_rep, current_epoch_hour);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_k));
        let ct_and_tag = cipher
            .encrypt(
                Nonce::from_slice(&aead_n),
                Payload {
                    msg: &inner_buf,
                    aad: &aad,
                },
            )
            .map_err(|_| MessengerError::CryptoFailure)?;
        aead_k.zeroize();
        inner_buf.zeroize();

        // 190 B ciphertext + 16 B Poly1305 tag = 206 B
        raw[48..254].copy_from_slice(&ct_and_tag);

        // Mine asymmetric BLAKE3-PoW and apply header XOR mask
        let difficulty = if (decay_class & 0x0F) >= 0x0C { 20 } else { POW_DIFFICULTY_MIN };
        seal_packet_with_pow(&mut raw, ctrl_plain, epoch_lsb_plain, difficulty, rng.next_u64());

        // Mark as seen locally so we don't re-ingest our own bounced frame
        let pkt = OuterPacket { raw };
        self.dtn.seen_cache.insert(pkt.short_id());
        Ok(raw)
    }

    /// Processes an incoming 254-byte frame from BLE 5.0 or Ultrasonic 19.5 kHz:
    /// - If addressed to us (O(1) oblivious tag hit), verifies Poly1305 and decrypts UTF-8 message.
    /// - Otherwise runs geometric TTL and stores in DTN buffer for automatic courier re-broadcast.
    pub fn receive_packet(
        &mut self,
        raw: &[u8],
        current_epoch_hour: u64,
        rng: &mut impl CryptoRngCore,
    ) -> ReceivedEvent {
        let decision = self.dtn.ingest_packet(raw, current_epoch_hour, rng);
        match decision {
            IngestDecision::DeliveredToLocalContact {
                contact_id,
                seq,
                epoch_hour,
            } => {
                let Ok(pkt) = OuterPacket::from_slice(raw) else {
                    return ReceivedEvent::Rejected { reason: "BAD_LEN" };
                };
                let Ok((ctrl, epoch_lsb)) = pkt.unmask_ctrl_and_epoch() else {
                    return ReceivedEvent::Rejected { reason: "BAD_HDR" };
                };
                let Some(session) = self.sessions.get(&contact_id) else {
                    return ReceivedEvent::Rejected { reason: "NO_SESSION" };
                };
                let aad = pkt.build_aad_core(ctrl.to_u8(), epoch_lsb);
                let (mut aead_k, aead_n) =
                    derive_aead_key_nonce(&session.rx_enc_key, pkt.ephemeral_rep(), epoch_hour);
                let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_k));
                let dec = cipher.decrypt(
                    Nonce::from_slice(&aead_n),
                    Payload {
                        msg: &pkt.raw[48..254],
                        aad: &aad,
                    },
                );
                aead_k.zeroize();

                let Ok(plain_vec) = dec else {
                    return ReceivedEvent::Rejected { reason: "AEAD_FAIL" };
                };
                let Ok(plain_arr): Result<[u8; INNER_PLAINTEXT_SIZE], _> = plain_vec.try_into() else {
                    return ReceivedEvent::Rejected { reason: "PLAIN_LEN" };
                };
                let Ok(inner) = InnerPlaintext::decode(&plain_arr) else {
                    return ReceivedEvent::Rejected { reason: "INNER_HDR" };
                };
                let text = String::from_utf8_lossy(&inner.payload).to_string();
                ReceivedEvent::DecryptedMessage {
                    contact_id,
                    sender_name: session.display_name.clone(),
                    seq,
                    text,
                    epoch_hour,
                }
            }
            IngestDecision::BufferedForRelay { sid, pow_bits } => {
                ReceivedEvent::BufferedForRelay { sid, pow_bits }
            }
            IngestDecision::DuplicateIgnored => ReceivedEvent::DuplicateIgnored,
            IngestDecision::DroppedGeometricDecay => ReceivedEvent::DroppedGeometricDecay,
            IngestDecision::RejectedInsufficientPow => ReceivedEvent::Rejected { reason: "LOW_POW" },
            IngestDecision::RejectedStaleEpoch => ReceivedEvent::Rejected { reason: "STALE_EPOCH" },
            _ => ReceivedEvent::Rejected { reason: "INVALID" },
        }
    }

    /// Selects the next buffered DTN courier packet (round-robin) for opportunistic re-broadcast
    /// during synchronized GNSS radio windows, pruning packets older than 72 hours.
    pub fn next_relay_packet(&mut self, current_epoch_hour: u64) -> Option<[u8; PACKET_SIZE]> {
        // Prune expired packets (> 72h)
        self.dtn.buffer.retain(|_, (pkt, _, _)| {
            pkt.unmask_ctrl_and_epoch()
                .ok()
                .and_then(|(_, lsb)| resolve_gnss_epoch(current_epoch_hour, lsb))
                .is_some()
        });
        if self.dtn.buffer.is_empty() {
            return None;
        }
        let keys: Vec<u64> = self.dtn.buffer.keys().copied().collect();
        let idx = self.relay_cursor % keys.len();
        self.relay_cursor = self.relay_cursor.wrapping_add(1);
        self.dtn.buffer.get(&keys[idx]).map(|(pkt, _, _)| pkt.raw)
    }
}
