use blake3::Hasher;
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TagChainState {
    pub contact_id: u32,
    pub chain_tag_key: [u8; 32],
    pub next_seq: u32,
}

impl TagChainState {
    pub fn advance(&mut self) -> ([u8; 32], u32) {
        let seq = self.next_seq;
        let msg_tag_key = blake3::keyed_hash(&self.chain_tag_key, b"AETHER_TAG_MSG_v1");
        let next_chain = blake3::keyed_hash(&self.chain_tag_key, b"AETHER_TAG_STEP_v1");
        self.chain_tag_key = *next_chain.as_bytes();
        self.next_seq = self.next_seq.wrapping_add(1);
        (*msg_tag_key.as_bytes(), seq)
    }
}

pub fn derive_session_tag(msg_tag_key: &[u8; 32], epoch_hour: u64) -> [u8; 8] {
    let mut h = Hasher::new_keyed(msg_tag_key);
    h.update(b"AETHER_TAG_v1");
    h.update(&epoch_hour.to_be_bytes());
    h.finalize().as_bytes()[0..8].try_into().unwrap()
}

pub fn derive_init_tag(dh_init: &[u8; 32], epoch_hour: u64, ephemeral_rep: &[u8; 32]) -> [u8; 8] {
    let mut h = Hasher::new_keyed(dh_init);
    h.update(b"AETHER_INIT_TAG_v1");
    h.update(&epoch_hour.to_be_bytes());
    h.update(ephemeral_rep);
    h.finalize().as_bytes()[0..8].try_into().unwrap()
}

#[derive(Default)]
pub struct ObliviousTagIndex {
    index: HashMap<[u8; 8], (u32, u32)>,
}

impl ObliviousTagIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, tag: [u8; 8], contact_id: u32, seq: u32) {
        self.index.insert(tag, (contact_id, seq));
    }

    pub fn lookup(&self, tag: &[u8; 8]) -> Option<(u32, u32)> {
        self.index.get(tag).copied()
    }
}
