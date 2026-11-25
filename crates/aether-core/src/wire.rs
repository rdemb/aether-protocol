use blake3::Hasher;
use rand_core::CryptoRngCore;
use thiserror::Error;

pub const PACKET_SIZE: usize = 254;
pub const INNER_PLAINTEXT_SIZE: usize = 190;
pub const MAX_INNER_PAYLOAD: usize = 182;
pub const PROTO_VER_V1: u8 = 0b00;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("Invalid packet length (expected exactly 254 bytes)")]
    InvalidPacketSize,
    #[error("Unsupported protocol version")]
    UnsupportedVersion,
    #[error("Inner payload exceeds 182-byte limit")]
    InvalidPayloadLength,
    #[error("Reserved inner_flags bits must be zero in v1")]
    NonZeroReservedBits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketClass {
    DataRatchet = 0b00,
    PqxdhInitFragment = 0b01,
    MinisketchSync = 0b10,
    HtlcVoucherCtrl = 0b11,
}

impl From<u8> for PacketClass {
    fn from(v: u8) -> Self {
        match v & 0b11 {
            0b00 => Self::DataRatchet,
            0b01 => Self::PqxdhInitFragment,
            0b10 => Self::MinisketchSync,
            _ => Self::HtlcVoucherCtrl,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtrlByte {
    pub proto_ver: u8,
    pub packet_class: PacketClass,
    pub decay_class: u8,
}

impl CtrlByte {
    pub fn to_u8(self) -> u8 {
        ((self.proto_ver & 0b11) << 6)
            | ((self.packet_class as u8 & 0b11) << 4)
            | (self.decay_class & 0x0F)
    }

    pub fn from_u8(b: u8) -> Result<Self, WireError> {
        let proto_ver = (b >> 6) & 0b11;
        if proto_ver != PROTO_VER_V1 {
            return Err(WireError::UnsupportedVersion);
        }
        Ok(Self {
            proto_ver,
            packet_class: PacketClass::from((b >> 4) & 0b11),
            decay_class: b & 0x0F,
        })
    }
}

/// Computes the 2-byte deterministic header XOR mask (RFC-0001 Section 2.3).
pub fn compute_header_mask(ephemeral_rep: &[u8; 32], pow_nonce: &[u8; 6]) -> [u8; 2] {
    let mut h = Hasher::new();
    h.update(b"AETHER_HDR_MASK_v1");
    h.update(ephemeral_rep);
    h.update(pow_nonce);
    let out = h.finalize();
    [out.as_bytes()[0], out.as_bytes()[1]]
}

/// Computes non-zero 64-bit Short ID for Minisketch over GF(2^64) (RFC-0001 Section 9.1).
pub fn compute_short_id(raw_packet: &[u8; PACKET_SIZE]) -> u64 {
    let mut h = Hasher::new();
    h.update(b"AETHER_SID_v1");
    h.update(raw_packet);
    let out = h.finalize();
    let sid = u64::from_le_bytes(out.as_bytes()[0..8].try_into().unwrap());
    if sid == 0 { 1 } else { sid }
}

/// 254-byte outer AETHER packet (RFC-0001 Section 2).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OuterPacket {
    pub raw: [u8; PACKET_SIZE],
}

impl OuterPacket {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != PACKET_SIZE {
            return Err(WireError::InvalidPacketSize);
        }
        let mut raw = [0u8; PACKET_SIZE];
        raw.copy_from_slice(bytes);
        Ok(Self { raw })
    }

    pub fn oblivious_tag(&self) -> &[u8; 8] {
        self.raw[0..8].try_into().unwrap()
    }

    pub fn ephemeral_rep(&self) -> &[u8; 32] {
        self.raw[8..40].try_into().unwrap()
    }

    pub fn pow_nonce(&self) -> &[u8; 6] {
        self.raw[40..46].try_into().unwrap()
    }

    pub fn unmask_ctrl_and_epoch(&self) -> Result<(CtrlByte, u8), WireError> {
        let mask = compute_header_mask(self.ephemeral_rep(), self.pow_nonce());
        let ctrl_plain = self.raw[46] ^ mask[0];
        let epoch_lsb_plain = self.raw[47] ^ mask[1];
        Ok((CtrlByte::from_u8(ctrl_plain)?, epoch_lsb_plain))
    }

    pub fn ciphertext(&self) -> &[u8; 190] {
        self.raw[48..238].try_into().unwrap()
    }

    pub fn aead_tag(&self) -> &[u8; 16] {
        self.raw[238..254].try_into().unwrap()
    }

    pub fn build_aad_core(&self, ctrl_plain: u8, epoch_lsb_plain: u8) -> [u8; 42] {
        let mut aad = [0u8; 42];
        aad[0..40].copy_from_slice(&self.raw[0..40]);
        aad[40] = ctrl_plain;
        aad[41] = epoch_lsb_plain;
        aad
    }

    pub fn short_id(&self) -> u64 {
        compute_short_id(&self.raw)
    }
}

/// 190-byte inner plaintext block with mandatory CSPRNG padding (RFC-0001 Section 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerPlaintext {
    pub codec_id: u8,
    pub frag_mode: u8,
    pub has_htlc: bool,
    pub priority: bool,
    pub seq_or_obj_id: u32,
    pub pn_or_esi: u16,
    pub payload: Vec<u8>,
}

impl InnerPlaintext {
    pub fn encode(&self, rng: &mut impl CryptoRngCore) -> Result<[u8; INNER_PLAINTEXT_SIZE], WireError> {
        if self.payload.len() > MAX_INNER_PAYLOAD {
            return Err(WireError::InvalidPayloadLength);
        }
        let mut buf = [0u8; INNER_PLAINTEXT_SIZE];
        let flags = ((self.codec_id & 0b11) << 6)
            | ((self.frag_mode & 0b11) << 4)
            | ((self.has_htlc as u8) << 3)
            | ((self.priority as u8) << 2);
        buf[0] = flags;
        buf[1..5].copy_from_slice(&self.seq_or_obj_id.to_be_bytes());
        buf[5..7].copy_from_slice(&self.pn_or_esi.to_be_bytes());
        buf[7] = self.payload.len() as u8;
        buf[8..8 + self.payload.len()].copy_from_slice(&self.payload);
        rng.fill_bytes(&mut buf[8 + self.payload.len()..INNER_PLAINTEXT_SIZE]);
        Ok(buf)
    }

    pub fn decode(buf: &[u8; INNER_PLAINTEXT_SIZE]) -> Result<Self, WireError> {
        let flags = buf[0];
        if (flags & 0b11) != 0 {
            return Err(WireError::NonZeroReservedBits);
        }
        let len = buf[7] as usize;
        if len > MAX_INNER_PAYLOAD {
            return Err(WireError::InvalidPayloadLength);
        }
        Ok(Self {
            codec_id: (flags >> 6) & 0b11,
            frag_mode: (flags >> 4) & 0b11,
            has_htlc: ((flags >> 3) & 1) == 1,
            priority: ((flags >> 2) & 1) == 1,
            seq_or_obj_id: u32::from_be_bytes(buf[1..5].try_into().unwrap()),
            pn_or_esi: u16::from_be_bytes(buf[5..7].try_into().unwrap()),
            payload: buf[8..8 + len].to_vec(),
        })
    }
}
