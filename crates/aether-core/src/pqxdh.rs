//! Hybrid Post-Quantum Key Agreement (X25519 + NIST FIPS 203 ML-KEM-768)
//! and RaptorQ fragmentation for 254-byte BLE transport (RFC-0001 Section 5).

use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem768};
use rand_core::CryptoRngCore;
use raptorq::{Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation};
use sha2::Sha512;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const INIT_PAYLOAD_SIZE: usize = 1152;
pub const RAPTORQ_SYMBOL_SIZE: u16 = 168; // Fits within 182 B InnerPlaintext payload

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridSessionKeys {
    pub sk_root: [u8; 32],
    pub tag_root_key: [u8; 32],
}

pub fn derive_pqxdh_keys(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    dh3: &[u8; 32],
    dh4: Option<&[u8; 32]>,
    ss_pq: &[u8; 32],
    ik_a_pub: &[u8; 32],
    ik_b_pub: &[u8; 32],
) -> HybridSessionKeys {
    let mut ikm = Vec::with_capacity(32 * 6);
    ikm.extend_from_slice(&[0xFFu8; 32]);
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    if let Some(d4) = dh4 {
        ikm.extend_from_slice(d4);
    }
    ikm.extend_from_slice(ss_pq);

    let hk = Hkdf::<Sha512>::new(Some(&[0u8; 64]), &ikm);
    ikm.zeroize();

    let mut info_root = Vec::with_capacity(20 + 64);
    info_root.extend_from_slice(b"AETHER_PQXDH_ROOT_v1");
    info_root.extend_from_slice(ik_a_pub);
    info_root.extend_from_slice(ik_b_pub);

    let mut info_tags = Vec::with_capacity(20 + 64);
    info_tags.extend_from_slice(b"AETHER_PQXDH_TAGS_v1");
    info_tags.extend_from_slice(ik_a_pub);
    info_tags.extend_from_slice(ik_b_pub);

    let mut sk_root = [0u8; 32];
    let mut tag_root_key = [0u8; 32];
    hk.expand(&info_root, &mut sk_root).expect("valid HKDF length");
    hk.expand(&info_tags, &mut tag_root_key).expect("valid HKDF length");

    HybridSessionKeys {
        sk_root,
        tag_root_key,
    }
}

/// Runs a complete hybrid ML-KEM-768 + X25519 initiator handshake, returning
/// the derived session keys and the 1088-byte post-quantum ciphertext.
pub fn initiator_pqxdh(
    ik_a: &StaticSecret,
    ek_a: &StaticSecret,
    ik_b_pub: &PublicKey,
    spk_b_pub: &PublicKey,
    pqspk_b: &<MlKem768 as KemCore>::EncapsulationKey,
    rng: &mut impl CryptoRngCore,
) -> (HybridSessionKeys, Ciphertext<MlKem768>) {
    let (ct_pq, ss_pq) = pqspk_b.encapsulate(rng).expect("ML-KEM-768 encaps failed");
    let dh1 = ik_a.diffie_hellman(spk_b_pub).to_bytes();
    let dh2 = ek_a.diffie_hellman(ik_b_pub).to_bytes();
    let dh3 = ek_a.diffie_hellman(spk_b_pub).to_bytes();
    let mut ss_arr = [0u8; 32];
    ss_arr.copy_from_slice(ss_pq.as_slice());

    let ik_a_pub = PublicKey::from(ik_a);
    let keys = derive_pqxdh_keys(
        &dh1,
        &dh2,
        &dh3,
        None,
        &ss_arr,
        ik_a_pub.as_bytes(),
        ik_b_pub.as_bytes(),
    );
    ss_arr.zeroize();
    (keys, ct_pq)
}

/// Runs the responder side of hybrid ML-KEM-768 + X25519 PQXDH.
pub fn responder_pqxdh(
    ik_b: &StaticSecret,
    spk_b: &StaticSecret,
    pqspk_b_dk: &<MlKem768 as KemCore>::DecapsulationKey,
    ik_a_pub: &PublicKey,
    ek_a_pub: &PublicKey,
    ct_pq: &Ciphertext<MlKem768>,
) -> HybridSessionKeys {
    let ss_pq = pqspk_b_dk.decapsulate(ct_pq).expect("ML-KEM-768 decaps failed");
    let dh1 = spk_b.diffie_hellman(ik_a_pub).to_bytes();
    let dh2 = ik_b.diffie_hellman(ek_a_pub).to_bytes();
    let dh3 = spk_b.diffie_hellman(ek_a_pub).to_bytes();
    let mut ss_arr = [0u8; 32];
    ss_arr.copy_from_slice(ss_pq.as_slice());

    let ik_b_pub = PublicKey::from(ik_b);
    let keys = derive_pqxdh_keys(
        &dh1,
        &dh2,
        &dh3,
        None,
        &ss_arr,
        ik_a_pub.as_bytes(),
        ik_b_pub.as_bytes(),
    );
    ss_arr.zeroize();
    keys
}

/// Fragments a 1152-byte PQXDH InitPayload into K=7 source + repair RaptorQ symbols (168 B each).
pub fn fragment_init_payload_raptorq(
    payload: &[u8; INIT_PAYLOAD_SIZE],
    repair_symbols: u32,
) -> (ObjectTransmissionInformation, Vec<Vec<u8>>) {
    let encoder = Encoder::with_defaults(payload, RAPTORQ_SYMBOL_SIZE);
    let oti = encoder.get_config();
    let packets = encoder
        .get_encoded_packets(repair_symbols)
        .into_iter()
        .map(|p| p.serialize())
        .collect();
    (oti, packets)
}

/// Reconstructs the 1152-byte InitPayload from any K received RaptorQ packets in any order.
pub fn reconstruct_init_payload_raptorq(
    oti: ObjectTransmissionInformation,
    serialized_packets: &[Vec<u8>],
) -> Option<[u8; INIT_PAYLOAD_SIZE]> {
    let mut decoder = Decoder::new(oti);
    for pkt_bytes in serialized_packets {
        let pkt = EncodingPacket::deserialize(pkt_bytes);
        if let Some(recovered) = decoder.decode(pkt) {
            if recovered.len() >= INIT_PAYLOAD_SIZE {
                let mut out = [0u8; INIT_PAYLOAD_SIZE];
                out.copy_from_slice(&recovered[..INIT_PAYLOAD_SIZE]);
                return Some(out);
            }
        }
    }
    None
}

/// Helper to expose ML-KEM-768 keypair generation cleanly.
pub fn generate_ml_kem_768(
    rng: &mut impl CryptoRngCore,
) -> (<MlKem768 as KemCore>::DecapsulationKey, <MlKem768 as KemCore>::EncapsulationKey, usize) {
    let (dk, ek) = MlKem768::generate(rng);
    let ek_len = ek.as_bytes().len();
    (dk, ek, ek_len)
}
