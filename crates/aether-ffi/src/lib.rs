//! Native Mobile FFI & Android JNI Bridge for `aether-core` (v0.4.0 Messenger App).

use std::sync::Mutex;

use aether_core::messenger::{AetherMessenger, ReceivedEvent};
use aether_core::minisketch::Minisketch;
use aether_core::ultrasonic_css::{decode_aether_254_pcm16, encode_aether_254_pcm16};
use aether_core::wire::PACKET_SIZE;
use rand_core::OsRng;

pub struct MobileAetherEngine {
    messenger: Mutex<AetherMessenger>,
}

impl MobileAetherEngine {
    pub fn new(max_buffer_packets: u32) -> Self {
        Self {
            messenger: Mutex::new(AetherMessenger::new(max_buffer_packets as usize)),
        }
    }

    pub fn pair_contact(
        &self,
        contact_id: u32,
        display_name: &str,
        passphrase: &str,
        is_initiator: bool,
        gnss_epoch_hour: u64,
    ) {
        let mut guard = self.messenger.lock().unwrap();
        guard.pair_contact(contact_id, display_name, passphrase, is_initiator, gnss_epoch_hour);
    }

    pub fn compose_message(
        &self,
        contact_id: u32,
        text: &str,
        decay_class: u8,
        gnss_epoch_hour: u64,
    ) -> Vec<u8> {
        let mut guard = self.messenger.lock().unwrap();
        let mut rng = OsRng;
        guard
            .compose_message_packet(contact_id, text, decay_class, gnss_epoch_hour, &mut rng)
            .map(|arr| arr.to_vec())
            .unwrap_or_default()
    }

    /// Processes any incoming 254 B frame (BLE 5.0 or Ultrasonic 19.5 kHz).
    /// Returns structured prefix:
    ///   - `MSG|<contact_id>|<sender_name>|<seq>|<utf8_text>`
    ///   - `RELAY|<sid_hex>|<pow_bits>`
    ///   - `DUP`, `DECAY`, `REJ|<reason>`
    pub fn ingest_frame(&self, frame: &[u8], gnss_epoch_hour: u64) -> String {
        let mut guard = self.messenger.lock().unwrap();
        let mut rng = OsRng;
        match guard.receive_packet(frame, gnss_epoch_hour, &mut rng) {
            ReceivedEvent::DecryptedMessage {
                contact_id,
                sender_name,
                seq,
                text,
                ..
            } => format!("MSG|{contact_id}|{sender_name}|{seq}|{text}"),
            ReceivedEvent::BufferedForRelay { sid, pow_bits } => {
                format!("RELAY|{sid:016x}|{pow_bits}")
            }
            ReceivedEvent::DuplicateIgnored => "DUP".to_string(),
            ReceivedEvent::DroppedGeometricDecay => "DECAY".to_string(),
            ReceivedEvent::Rejected { reason } => format!("REJ|{reason}"),
        }
    }

    pub fn pop_next_relay_packet(&self, gnss_epoch_hour: u64) -> Vec<u8> {
        let mut guard = self.messenger.lock().unwrap();
        guard
            .next_relay_packet(gnss_epoch_hour)
            .map(|a| a.to_vec())
            .unwrap_or_default()
    }

    pub fn export_minisketch_176b(&self) -> Vec<u8> {
        let guard = self.messenger.lock().unwrap();
        let mut sketch = Minisketch::new();
        for &sid in guard.dtn.buffer.keys() {
            sketch.add(sid);
        }
        sketch.to_bytes().to_vec()
    }

    pub fn encode_ultrasonic_254(&self, frame: &[u8]) -> Vec<i16> {
        let Ok(arr): Result<[u8; PACKET_SIZE], _> = frame.try_into() else {
            return Vec::new();
        };
        encode_aether_254_pcm16(&arr)
    }

    pub fn decode_ultrasonic_254(&self, pcm16: &[i16]) -> Option<Vec<u8>> {
        decode_aether_254_pcm16(pcm16).ok().map(|b| b.to_vec())
    }

    pub fn buffer_count(&self) -> u32 {
        self.messenger.lock().unwrap().dtn.buffer.len() as u32
    }
}

#[cfg(target_os = "android")]
mod android_jni {
    use super::*;
    use jni::objects::{JByteArray, JClass, JShortArray, JString};
    use jni::sys::{jboolean, jbyteArray, jint, jlong, jshortArray, jstring};
    use jni::JNIEnv;

    #[no_mangle]
    pub extern "system" fn Java_org_aether_radio_AetherNativeBridge_nativeCreateEngine(
        _env: JNIEnv,
        _class: JClass,
        max_buffer_packets: jint,
    ) -> jlong {
        Box::into_raw(Box::new(MobileAetherEngine::new(max_buffer_packets.max(16) as u32))) as jlong
    }

    #[no_mangle]
    pub extern "system" fn Java_org_aether_radio_AetherNativeBridge_nativeDestroyEngine(
        _env: JNIEnv,
        _class: JClass,
        handle: jlong,
    ) {
        if handle != 0 {
            unsafe {
                drop(Box::from_raw(handle as *mut MobileAetherEngine));
            }
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_org_aether_radio_AetherNativeBridge_nativePairContact(
        mut env: JNIEnv,
        _class: JClass,
        handle: jlong,
        contact_id: jint,
        display_name: JString,
        passphrase: JString,
        is_initiator: jboolean,
        gnss_epoch_hour: jlong,
    ) {
        if handle == 0 {
            return;
        }
        let Ok(name_str) = env.get_string(&display_name) else { return };
        let Ok(pass_str) = env.get_string(&passphrase) else { return };
        let engine = unsafe { &*(handle as *const MobileAetherEngine) };
        engine.pair_contact(
            contact_id.max(0) as u32,
            &name_str.to_string_lossy(),
            &pass_str.to_string_lossy(),
            is_initiator != 0,
            gnss_epoch_hour.max(0) as u64,
        );
    }

    #[no_mangle]
    pub extern "system" fn Java_org_aether_radio_AetherNativeBridge_nativeComposeMessage(
        mut env: JNIEnv,
        _class: JClass,
        handle: jlong,
        contact_id: jint,
        text: JString,
        decay_class: jint,
        gnss_epoch_hour: jlong,
    ) -> jbyteArray {
        if handle == 0 {
            return env.byte_array_from_slice(&[]).unwrap().into_raw();
        }
        let Ok(txt) = env.get_string(&text) else {
            return env.byte_array_from_slice(&[]).unwrap().into_raw();
        };
        let engine = unsafe { &*(handle as *const MobileAetherEngine) };
        let pkt = engine.compose_message(
            contact_id.max(0) as u32,
            &txt.to_string_lossy(),
            (decay_class & 0x0F) as u8,
            gnss_epoch_hour.max(0) as u64,
        );
        env.byte_array_from_slice(&pkt).unwrap().into_raw()
    }

    #[no_mangle]
    pub extern "system" fn Java_org_aether_radio_AetherNativeBridge_nativeIngestFrame(
        env: JNIEnv,
        _class: JClass,
        handle: jlong,
        frame: JByteArray,
        gnss_epoch_hour: jlong,
    ) -> jstring {
        if handle == 0 {
            return env.new_string("REJ|NULL_HANDLE").unwrap().into_raw();
        }
        let Ok(bytes) = env.convert_byte_array(frame) else {
            return env.new_string("REJ|BAD_ARRAY").unwrap().into_raw();
        };
        let engine = unsafe { &*(handle as *const MobileAetherEngine) };
        let res = engine.ingest_frame(&bytes, gnss_epoch_hour.max(0) as u64);
        env.new_string(res).unwrap().into_raw()
    }

    #[no_mangle]
    pub extern "system" fn Java_org_aether_radio_AetherNativeBridge_nativePopRelayPacket(
        env: JNIEnv,
        _class: JClass,
        handle: jlong,
        gnss_epoch_hour: jlong,
    ) -> jbyteArray {
        if handle == 0 {
            return env.byte_array_from_slice(&[]).unwrap().into_raw();
        }
        let engine = unsafe { &*(handle as *const MobileAetherEngine) };
        let pkt = engine.pop_next_relay_packet(gnss_epoch_hour.max(0) as u64);
        env.byte_array_from_slice(&pkt).unwrap().into_raw()
    }

    #[no_mangle]
    pub extern "system" fn Java_org_aether_radio_AetherNativeBridge_nativeExportMinisketch(
        env: JNIEnv,
        _class: JClass,
        handle: jlong,
    ) -> jbyteArray {
        if handle == 0 {
            return env.byte_array_from_slice(&[]).unwrap().into_raw();
        }
        let engine = unsafe { &*(handle as *const MobileAetherEngine) };
        env.byte_array_from_slice(&engine.export_minisketch_176b())
            .unwrap()
            .into_raw()
    }

    #[no_mangle]
    pub extern "system" fn Java_org_aether_radio_AetherNativeBridge_nativeEncodeUltrasonicPcm16(
        env: JNIEnv,
        _class: JClass,
        handle: jlong,
        frame: JByteArray,
    ) -> jshortArray {
        if handle == 0 {
            return env.new_short_array(0).unwrap().into_raw();
        }
        let Ok(bytes) = env.convert_byte_array(frame) else {
            return env.new_short_array(0).unwrap().into_raw();
        };
        let engine = unsafe { &*(handle as *const MobileAetherEngine) };
        let pcm = engine.encode_ultrasonic_254(&bytes);
        let arr = env.new_short_array(pcm.len() as i32).unwrap();
        env.set_short_array_region(&arr, 0, &pcm).unwrap();
        arr.into_raw()
    }

    #[no_mangle]
    pub extern "system" fn Java_org_aether_radio_AetherNativeBridge_nativeDecodeUltrasonicPcm16(
        env: JNIEnv,
        _class: JClass,
        handle: jlong,
        pcm: JShortArray,
    ) -> jbyteArray {
        if handle == 0 {
            return env.byte_array_from_slice(&[]).unwrap().into_raw();
        }
        let Ok(len) = env.get_array_length(&pcm) else {
            return env.byte_array_from_slice(&[]).unwrap().into_raw();
        };
        let mut buf = vec![0i16; len.max(0) as usize];
        if env.get_short_array_region(&pcm, 0, &mut buf).is_err() {
            return env.byte_array_from_slice(&[]).unwrap().into_raw();
        }
        let engine = unsafe { &*(handle as *const MobileAetherEngine) };
        match engine.decode_ultrasonic_254(&buf) {
            Some(pkt) => env.byte_array_from_slice(&pkt).unwrap().into_raw(),
            None => env.byte_array_from_slice(&[]).unwrap().into_raw(),
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_org_aether_radio_AetherNativeBridge_nativeGetBufferCount(
        _env: JNIEnv,
        _class: JClass,
        handle: jlong,
    ) -> jint {
        if handle == 0 {
            return 0;
        }
        let engine = unsafe { &*(handle as *const MobileAetherEngine) };
        engine.buffer_count() as jint
    }
}
