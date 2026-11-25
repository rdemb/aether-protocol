use std::collections::{HashMap, HashSet};
use rand_core::CryptoRngCore;
use crate::decay::{resolve_gnss_epoch, should_relay_geometric};
use crate::pow::verify_packet_pow;
use crate::tag::ObliviousTagIndex;
use crate::wire::{OuterPacket, PacketClass};

pub const BARTER_MAX_DEFICIT: i32 = 2;

#[derive(Debug, PartialEq, Eq)]
pub enum IngestDecision {
    RejectedInvalid,
    RejectedStaleEpoch,
    RejectedInsufficientPow,
    DuplicateIgnored,
    HandleMinisketchSync,
    DeliveredToLocalContact { contact_id: u32, seq: u32, epoch_hour: u64 },
    TryPqxdhInitDecrypt { epoch_hour: u64 },
    BufferedForRelay { sid: u64, pow_bits: u8 },
    DroppedGeometricDecay,
}

#[derive(Default)]
pub struct BarterSession {
    sent_to_peer: i32,
    received_from_peer: i32,
}

impl BarterSession {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn can_send_next(&self) -> bool {
        (self.sent_to_peer - self.received_from_peer) < BARTER_MAX_DEFICIT
    }

    pub fn record_sent(&mut self) {
        self.sent_to_peer += 1;
    }

    pub fn record_valid_received(&mut self) {
        self.received_from_peer += 1;
    }
}

pub struct DtnNode {
    pub max_buffer_packets: usize,
    pub buffer: HashMap<u64, (OuterPacket, u8, u64)>,
    pub seen_cache: HashSet<u64>,
    pub tag_index: ObliviousTagIndex,
}

impl DtnNode {
    pub fn new(max_buffer_packets: usize) -> Self {
        Self {
            max_buffer_packets,
            buffer: HashMap::new(),
            seen_cache: HashSet::new(),
            tag_index: ObliviousTagIndex::new(),
        }
    }

    pub fn buffer_fill_pct(&self) -> u8 {
        if self.max_buffer_packets == 0 {
            return 100;
        }
        ((self.buffer.len() * 100) / self.max_buffer_packets).min(100) as u8
    }

    pub fn ingest_packet(
        &mut self,
        raw: &[u8],
        current_epoch_hour: u64,
        rng: &mut impl CryptoRngCore,
    ) -> IngestDecision {
        let Ok(pkt) = OuterPacket::from_slice(raw) else {
            return IngestDecision::RejectedInvalid;
        };
        let Ok((ctrl, epoch_lsb)) = pkt.unmask_ctrl_and_epoch() else {
            return IngestDecision::RejectedInvalid;
        };
        let Some(epoch_hour) = resolve_gnss_epoch(current_epoch_hour, epoch_lsb) else {
            return IngestDecision::RejectedStaleEpoch;
        };
        let Ok(pow_bits) = verify_packet_pow(&pkt, self.buffer_fill_pct()) else {
            return IngestDecision::RejectedInsufficientPow;
        };
        let sid = pkt.short_id();
        if !self.seen_cache.insert(sid) {
            return IngestDecision::DuplicateIgnored;
        }
        match ctrl.packet_class {
            PacketClass::MinisketchSync => return IngestDecision::HandleMinisketchSync,
            PacketClass::DataRatchet => {
                if let Some((contact_id, seq)) = self.tag_index.lookup(pkt.oblivious_tag()) {
                    return IngestDecision::DeliveredToLocalContact {
                        contact_id,
                        seq,
                        epoch_hour,
                    };
                }
            }
            PacketClass::PqxdhInitFragment => {
                return IngestDecision::TryPqxdhInitDecrypt { epoch_hour };
            }
            PacketClass::HtlcVoucherCtrl => {}
        }
        if should_relay_geometric(ctrl.decay_class, rng) {
            self.insert_with_pow_eviction(sid, pkt, pow_bits, epoch_hour);
            IngestDecision::BufferedForRelay { sid, pow_bits }
        } else {
            IngestDecision::DroppedGeometricDecay
        }
    }

    fn insert_with_pow_eviction(&mut self, sid: u64, pkt: OuterPacket, pow_bits: u8, epoch_hour: u64) {
        if self.buffer.len() >= self.max_buffer_packets {
            if let Some((&victim_sid, _)) = self
                .buffer
                .iter()
                .min_by_key(|(_, (_, bits, ep))| (*bits, *ep))
            {
                self.buffer.remove(&victim_sid);
            }
        }
        self.buffer.insert(sid, (pkt, pow_bits, epoch_hour));
    }
}
