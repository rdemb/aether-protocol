package org.aether.radio

import android.annotation.SuppressLint
import android.media.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Android 48 kHz PCM-16 Ultrasonic CSS Transceiver (18.3 - 20.7 kHz).
 * Operates in 100% Airplane Mode (zero RF emission: BLE OFF, Wi-Fi OFF, SIM OFF).
 */
class AetherUltrasonicModem(private val engine: AetherNativeBridge) {

    companion object {
        const val SAMPLE_RATE = 48_000
        const val RX_WINDOW_SECONDS = 15 // Captures full 10.35 s 254 B frame + margin
    }

    /** Synthesizes and plays a 254-byte AETHER frame through the smartphone speaker at 19.5 kHz. */
    suspend fun transmitFrame254(frame254: ByteArray): Int = withContext(Dispatchers.IO) {
        val pcm16 = engine.encodeUltrasonicPcm16(frame254)
        if (pcm16.isEmpty()) return@withContext 0

        val minBuf = AudioTrack.getMinBufferSize(
            SAMPLE_RATE,
            AudioFormat.CHANNEL_OUT_MONO,
            AudioFormat.ENCODING_PCM_16BIT
        )
        val track = AudioTrack.Builder()
            .setAudioAttributes(
                AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_MEDIA)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                    .build()
            )
            .setAudioFormat(
                AudioFormat.Builder()
                    .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                    .setSampleRate(SAMPLE_RATE)
                    .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
                    .build()
            )
            .setBufferSizeInBytes(maxOf(minBuf, pcm16.size * 2))
            .setTransferMode(AudioTrack.MODE_STATIC)
            .build()

        try {
            track.write(pcm16, 0, pcm16.size)
            track.play()
            val durationMs = (pcm16.size * 1000L) / SAMPLE_RATE + 150L
            kotlinx.coroutines.delay(durationMs)
            pcm16.size
        } finally {
            runCatching { track.stop() }
            track.release()
        }
    }

    /**
     * Records 48 kHz uncompressed audio via AudioSource.UNPROCESSED (avoiding voice AGC/LPF
     * that would attenuate 19.5 kHz) and runs the Rust CSS + Reed-Solomon decoder.
     */
    @SuppressLint("MissingPermission")
    suspend fun listenForFrame254(seconds: Int = RX_WINDOW_SECONDS): ByteArray? = withContext(Dispatchers.IO) {
        val totalSamples = SAMPLE_RATE * seconds
        val minBuf = AudioRecord.getMinBufferSize(
            SAMPLE_RATE,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT
        )
        val source = MediaRecorder.AudioSource.UNPROCESSED
        val recorder = runCatching {
            AudioRecord(source, SAMPLE_RATE, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT, maxOf(minBuf * 2, 16384))
        }.getOrElse {
            AudioRecord(MediaRecorder.AudioSource.MIC, SAMPLE_RATE, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT, maxOf(minBuf * 2, 16384))
        }

        val capture = ShortArray(totalSamples)
        var offset = 0
        try {
            recorder.startRecording()
            while (offset < totalSamples) {
                val read = recorder.read(capture, offset, minOf(4096, totalSamples - offset))
                if (read <= 0) break
                offset += read
            }
        } finally {
            runCatching { recorder.stop() }
            recorder.release()
        }

        val decoded = engine.decodeUltrasonicPcm16(capture)
        if (decoded.size == 254) decoded else null
    }
}
