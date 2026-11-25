package org.aether.radio

import java.io.Closeable

/**
 * Direct JNI bridge to `libaether_ffi.so` (Rust `aether-core` RFC-0001/0002 + CSS 19.5 kHz DSP).
 */
class AetherNativeBridge(maxBufferPackets: Int = 120) : Closeable {

    private var nativeHandle: Long = nativeCreateEngine(maxBufferPackets)

    fun pairContact(
        contactId: Int,
        displayName: String,
        passphrase: String,
        isInitiator: Boolean,
        gnssEpochHour: Long
    ) {
        check(nativeHandle != 0L) { "Engine already closed" }
        nativePairContact(nativeHandle, contactId, displayName, passphrase, isInitiator, gnssEpochHour)
    }

    fun composeMessage(
        contactId: Int,
        text: String,
        decayClass: Int = 0x08,
        gnssEpochHour: Long
    ): ByteArray {
        check(nativeHandle != 0L) { "Engine already closed" }
        return nativeComposeMessage(nativeHandle, contactId, text, decayClass, gnssEpochHour)
    }

    fun ingestFrame(frame254: ByteArray, gnssEpochHour: Long): String {
        check(nativeHandle != 0L) { "Engine already closed" }
        return nativeIngestFrame(nativeHandle, frame254, gnssEpochHour)
    }

    fun popNextRelayPacket(gnssEpochHour: Long): ByteArray {
        check(nativeHandle != 0L) { "Engine already closed" }
        return nativePopRelayPacket(nativeHandle, gnssEpochHour)
    }

    fun exportMinisketch176B(): ByteArray {
        check(nativeHandle != 0L) { "Engine already closed" }
        return nativeExportMinisketch(nativeHandle)
    }

    fun encodeUltrasonicPcm16(frame254: ByteArray): ShortArray {
        check(nativeHandle != 0L) { "Engine already closed" }
        return nativeEncodeUltrasonicPcm16(nativeHandle, frame254)
    }

    fun decodeUltrasonicPcm16(pcm16: ShortArray): ByteArray {
        check(nativeHandle != 0L) { "Engine already closed" }
        return nativeDecodeUltrasonicPcm16(nativeHandle, pcm16)
    }

    fun bufferCount(): Int {
        if (nativeHandle == 0L) return 0
        return nativeGetBufferCount(nativeHandle)
    }

    override fun close() {
        val h = nativeHandle
        if (h != 0L) {
            nativeHandle = 0L
            nativeDestroyEngine(h)
        }
    }

    companion object {
        init {
            System.loadLibrary("aether_ffi")
        }

        @JvmStatic private external fun nativeCreateEngine(maxBufferPackets: Int): Long
        @JvmStatic private external fun nativeDestroyEngine(handle: Long)
        @JvmStatic private external fun nativePairContact(
            handle: Long, contactId: Int, displayName: String, passphrase: String,
            isInitiator: Boolean, gnssEpochHour: Long
        )
        @JvmStatic private external fun nativeComposeMessage(
            handle: Long, contactId: Int, text: String, decayClass: Int, gnssEpochHour: Long
        ): ByteArray
        @JvmStatic private external fun nativeIngestFrame(handle: Long, frame: ByteArray, gnssEpochHour: Long): String
        @JvmStatic private external fun nativePopRelayPacket(handle: Long, gnssEpochHour: Long): ByteArray
        @JvmStatic private external fun nativeExportMinisketch(handle: Long): ByteArray
        @JvmStatic private external fun nativeEncodeUltrasonicPcm16(handle: Long, frame: ByteArray): ShortArray
        @JvmStatic private external fun nativeDecodeUltrasonicPcm16(handle: Long, pcm: ShortArray): ByteArray
        @JvmStatic private external fun nativeGetBufferCount(handle: Long): Int
    }
}
