package org.aether.radio

import android.bluetooth.le.ScanRecord

/**
 * Zero-Fingerprint Manufacturer-ID Folding (AETHER-IMPL-0002 Section 1).
 *
 * Encodes a 254-byte AETHER packet into standard BLE AD Type 0xFF without any static
 * company identifier:
 *  - `manufacturerId` (16-bit LE) = `packet[0..2]` (first 2 random bytes of oblivious_tag)
 *  - `manufacturerSpecificData`   = `packet[2..254]` (exact 252 bytes)
 */
object BleFrameFolder {
    const val AETHER_PACKET_SIZE = 254
    const val FOLDED_DATA_SIZE = 252

    data class FoldedBlePayload(
        val manufacturerId: Int,
        val payload252: ByteArray,
    )

    fun packForBle(packet254: ByteArray): FoldedBlePayload {
        require(packet254.size == AETHER_PACKET_SIZE) {
            "Expected exactly 254-byte AETHER packet, got ${packet254.size}"
        }
        val lsb = packet254[0].toInt() and 0xFF
        val msb = packet254[1].toInt() and 0xFF
        val dynamicMfgId = lsb or (msb shl 8)
        val rest252 = packet254.copyOfRange(2, AETHER_PACKET_SIZE)
        return FoldedBlePayload(dynamicMfgId, rest252)
    }

    /**
     * Extracts candidate 254-byte AETHER packets from any received BLE ScanRecord.
     * Non-AETHER frames are rejected in ~0.5 us by BLAKE3-PoW inside `aether-core`.
     */
    fun extractCandidates(record: ScanRecord?): List<ByteArray> {
        val mfgMap = record?.manufacturerSpecificData ?: return emptyList()
        if (mfgMap.size() == 0) return emptyList()

        val candidates = ArrayList<ByteArray>(1)
        for (i in 0 until mfgMap.size()) {
            val mfgId = mfgMap.keyAt(i)
            val data = mfgMap.valueAt(i) ?: continue
            if (data.size == FOLDED_DATA_SIZE) {
                val pkt = ByteArray(AETHER_PACKET_SIZE)
                pkt[0] = (mfgId and 0xFF).toByte()
                pkt[1] = ((mfgId ushr 8) and 0xFF).toByte()
                System.arraycopy(data, 0, pkt, 2, FOLDED_DATA_SIZE)
                candidates.add(pkt)
            }
        }
        return candidates
    }
}
