package org.aether.radio

import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.bluetooth.le.*
import android.content.Intent
import android.os.BatteryManager
import android.os.Binder
import android.os.IBinder
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.*
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentLinkedQueue

data class ChatMessage(
    val sender: String,
    val text: String,
    val isMine: Boolean,
    val transport: String, // "BLE 5.0", "CSS 19.5kHz", "DTN Kurier"
    val timestamp: String,
    val status: String = "Wysłano (254 B)"
)

data class RadioTelemetry(
    val powerMode: PowerMode,
    val codedPhySupported: Boolean,
    val gnssCalibrated: Boolean,
    val relayBufferCount: Int,
    val relayedOutCount: Int,
    val lastRssi: Int?,
    val pairedPeerName: String?
)

/**
 * AETHER v0.4.0 Ultra-Low-Power Off-Grid Messenger Service:
 *  - Full E2E ChaCha20-Poly1305 + Elligator-2 + BLAKE3-PoW messaging via Rust JNI
 *  - Automatic Kineto-DTN courier re-broadcast (battery-aware: pauses relay below 20% battery)
 *  - Adaptive GNSS slot duty-cycling (ECO 0.8% / DTN 3.6% / ACTIVE chat)
 *  - Dual L0 transport: BLE 5.0 Coded PHY S=8 + Air-Gapped 19.5 kHz Ultrasonic CSS
 */
class AetherBleService : Service() {

    inner class LocalBinder : Binder() {
        fun getService(): AetherBleService = this@AetherBleService
    }

    private val binder = LocalBinder()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val timeFmt = SimpleDateFormat("HH:mm", Locale.getDefault())

    private lateinit var bluetoothAdapter: BluetoothAdapter
    private lateinit var batteryManager: BatteryManager
    private lateinit var gnssScheduler: GnssSlotScheduler
    private lateinit var engine: AetherNativeBridge
    private lateinit var ultrasonicModem: AetherUltrasonicModem

    private val txQueue = ConcurrentLinkedQueue<ByteArray>()
    val messageHistory = ArrayList<ChatMessage>()

    private var slotJob: Job? = null
    private var activeAdvCallback: AdvertisingSetCallback? = null
    private var slotCounter = 0
    private var relayedOutCount = 0
    private var lastRssi: Int? = null
    private var pairedPeerName: String? = null
    private var pairedContactId: Int = 1

    @Volatile var onChatUpdated: ((ChatMessage) -> Unit)? = null
    @Volatile var onTelemetryUpdated: ((RadioTelemetry) -> Unit)? = null
    @Volatile var onStatusToast: ((String) -> Unit)? = null

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onCreate() {
        super.onCreate()
        val bm = getSystemService(BLUETOOTH_SERVICE) as BluetoothManager
        bluetoothAdapter = bm.adapter
        batteryManager = getSystemService(BATTERY_SERVICE) as BatteryManager
        gnssScheduler = GnssSlotScheduler(this)
        engine = AetherNativeBridge(maxBufferPackets = 120)
        ultrasonicModem = AetherUltrasonicModem(engine)

        startForeground(1001, buildNotification("AETHER Off-Grid • Czuwanie ECO"))
        gnssScheduler.startPassiveCalibration()

        // Restore saved pairing if present
        restoreSavedPairing()
        startGnssPulseLoop()
        pushTelemetry()
    }

    override fun onDestroy() {
        slotJob?.cancel()
        stopBleWindow()
        gnssScheduler.stopCalibration()
        engine.close()
        scope.cancel()
        super.onDestroy()
    }

    fun setPowerMode(mode: PowerMode) {
        gnssScheduler.powerMode = mode
        updateNotification("AETHER • ${mode.label} • Bufor DTN: ${engine.bufferCount()}")
        pushTelemetry()
    }

    fun configurePairing(peerName: String, passphrase: String, isInitiator: Boolean) {
        val epoch = gnssScheduler.currentGnssEpochHour()
        engine.pairContact(pairedContactId, peerName, passphrase, isInitiator, epoch)
        pairedPeerName = peerName
        getSharedPreferences("aether_prefs", MODE_PRIVATE).edit()
            .putString("peer_name", peerName)
            .putString("passphrase", passphrase)
            .putBoolean("is_initiator", isInitiator)
            .apply()
        onStatusToast?.invoke("Sparowano offline z: $peerName (E2E + ślepe tagi aktywne)")
        pushTelemetry()
    }

    private fun restoreSavedPairing() {
        val prefs = getSharedPreferences("aether_prefs", MODE_PRIVATE)
        val name = prefs.getString("peer_name", null) ?: return
        val pass = prefs.getString("passphrase", null) ?: return
        val init = prefs.getBoolean("is_initiator", true)
        val epoch = gnssScheduler.currentGnssEpochHour()
        engine.pairContact(pairedContactId, name, pass, init, epoch)
        pairedPeerName = name
    }

    fun isPaired(): Boolean = pairedPeerName != null

    /** Sends an E2E encrypted UTF-8 message over BLE 5.0 Coded PHY (and Kineto-DTN relays). */
    fun sendTextViaBle(text: String, urgent: Boolean = false) {
        if (pairedPeerName == null) {
            onStatusToast?.invoke("Najpierw sparuj telefon (ikona klucza u góry).")
            return
        }
        scope.launch {
            val epoch = gnssScheduler.currentGnssEpochHour()
            val decay = if (urgent) 0x0F else 0x08
            val t0 = System.nanoTime()
            val pkt254 = engine.composeMessage(pairedContactId, text, decay, epoch)
            val powMs = (System.nanoTime() - t0) / 1_000_000L
            if (pkt254.size != 254) {
                onStatusToast?.invoke("Wiadomość za długa (limit atomowej ramki: 182 bajty UTF-8).")
                return@launch
            }
            // Queue twice across adjacent GNSS slots to maximize capture probability on moving peers
            txQueue.add(pkt254)
            txQueue.add(pkt254)
            val msg = ChatMessage(
                sender = "Ty",
                text = text,
                isMine = true,
                transport = if (bluetoothAdapter.isLeCodedPhySupported) "BLE 5.0 Coded" else "BLE 5.0",
                timestamp = timeFmt.format(Date()),
                status = "Zaszyfrowano 254 B • PoW ${powMs} ms"
            )
            synchronized(messageHistory) { messageHistory.add(msg) }
            onChatUpdated?.invoke(msg)
            pushTelemetry()
        }
    }

    /** Sends an E2E encrypted UTF-8 message over 19.5 kHz Ultrasonic CSS (100% Airplane Mode!). */
    fun sendTextViaUltrasonic(text: String) {
        if (pairedPeerName == null) {
            onStatusToast?.invoke("Najpierw sparuj telefon (ikona klucza u góry).")
            return
        }
        scope.launch {
            val epoch = gnssScheduler.currentGnssEpochHour()
            val pkt254 = engine.composeMessage(pairedContactId, text, 0x08, epoch)
            if (pkt254.size != 254) {
                onStatusToast?.invoke("Limit ramki: 182 bajty UTF-8.")
                return@launch
            }
            val msg = ChatMessage(
                sender = "Ty",
                text = text,
                isMine = true,
                transport = "Ultradźwięk 19.5 kHz",
                timestamp = timeFmt.format(Date()),
                status = "Nadawanie akustyczne (10.3 s)..."
            )
            synchronized(messageHistory) { messageHistory.add(msg) }
            onChatUpdated?.invoke(msg)
            ultrasonicModem.transmitFrame254(pkt254)
            onStatusToast?.invoke("Zakończono nadawanie ultradźwiękiem 19.5 kHz.")
        }
    }

    /** Listens for 12 seconds on the 48 kHz UNPROCESSED microphone for an air-gapped 19.5 kHz frame. */
    fun listenUltrasonic() {
        scope.launch {
            onStatusToast?.invoke("Nasłuch ultradźwięku 19.5 kHz (15 s)...")
            val pkt254 = ultrasonicModem.listenForFrame254(15)
            if (pkt254 != null) {
                handleIncomingFrame(pkt254, "Ultradźwięk 19.5 kHz", null)
            } else {
                onStatusToast?.invoke("Brak ramki 19.5 kHz w tym oknie.")
            }
        }
    }

    private fun startGnssPulseLoop() {
        slotJob = scope.launch {
            while (isActive) {
                val waitMs = gnssScheduler.delayToNextSlotMs()
                delay(waitMs)
                slotCounter++
                openRadioWindow(gnssScheduler.powerMode.activeWindowMs)
            }
        }
    }

    @SuppressLint("MissingPermission")
    private suspend fun openRadioWindow(durationMs: Long) {
        val scanner = bluetoothAdapter.bluetoothLeScanner
        val advertiser = bluetoothAdapter.bluetoothLeAdvertiser
        if (scanner == null || advertiser == null) return

        // 1. Scan for incoming Extended Advertising frames
        val scanSettings = ScanSettings.Builder()
            .setLegacy(false)
            .setPhy(ScanSettings.PHY_LE_ALL_SUPPORTED)
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()
        runCatching { scanner.startScan(null, scanSettings, scanCallback) }

        // 2. Transmit own queued message OR automatic DTN courier relay every 3rd slot (if battery > 20%)
        var pktToSend = txQueue.poll()
        var isCourierRelay = false
        if (pktToSend == null && slotCounter % 3 == 0 && batteryLevelPct() > 20) {
            val relayCandidate = engine.popNextRelayPacket(gnssScheduler.currentGnssEpochHour())
            if (relayCandidate.size == 254) {
                pktToSend = relayCandidate
                isCourierRelay = true
            }
        }

        if (pktToSend != null) {
            broadcastPacket254(advertiser, pktToSend)
            if (isCourierRelay) {
                relayedOutCount++
                pushTelemetry()
            }
        }

        delay(durationMs)
        stopBleWindow()
    }

    @SuppressLint("MissingPermission")
    private fun broadcastPacket254(advertiser: BluetoothLeAdvertiser, pkt254: ByteArray) {
        val folded = BleFrameFolder.packForBle(pkt254)
        val useCoded = bluetoothAdapter.isLeCodedPhySupported
        val phy = if (useCoded) BluetoothDevice.PHY_LE_CODED else BluetoothDevice.PHY_LE_1M

        val paramsBuilder = AdvertisingSetParameters.Builder()
            .setLegacyMode(false)
            .setConnectable(false)
            .setScannable(false)
            .setPrimaryPhy(phy)
            .setSecondaryPhy(phy)
            .setInterval(AdvertisingSetParameters.INTERVAL_MIN)
            .setTxPowerLevel(AdvertisingSetParameters.TX_POWER_HIGH)
            .setAnonymous(true)

        val advData = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .setIncludeTxPowerLevel(false)
            .addManufacturerData(folded.manufacturerId, folded.payload252)
            .build()

        val cb = object : AdvertisingSetCallback() {}
        activeAdvCallback = cb
        runCatching {
            advertiser.startAdvertisingSet(paramsBuilder.build(), advData, null, null, null, cb)
        }.onFailure {
            paramsBuilder.setAnonymous(false)
            runCatching {
                advertiser.startAdvertisingSet(paramsBuilder.build(), advData, null, null, null, cb)
            }
        }
    }

    @SuppressLint("MissingPermission")
    private fun stopBleWindow() {
        runCatching { bluetoothAdapter.bluetoothLeScanner?.stopScan(scanCallback) }
        activeAdvCallback?.let { cb ->
            runCatching { bluetoothAdapter.bluetoothLeAdvertiser?.stopAdvertisingSet(cb) }
            activeAdvCallback = null
        }
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val candidates = BleFrameFolder.extractCandidates(result.scanRecord)
            if (candidates.isEmpty()) return
            for (pkt254 in candidates) {
                handleIncomingFrame(pkt254, "BLE 5.0", result.rssi)
            }
        }
    }

    private fun handleIncomingFrame(pkt254: ByteArray, transport: String, rssi: Int?) {
        val epoch = gnssScheduler.currentGnssEpochHour()
        val res = engine.ingestFrame(pkt254, epoch)
        when {
            res.startsWith("MSG|") -> {
                val parts = res.split("|", limit = 5)
                if (parts.size == 5) {
                    lastRssi = rssi
                    val senderName = parts[2]
                    val seq = parts[3]
                    val text = parts[4]
                    val rssiLabel = if (rssi != null) " • ${rssi} dBm" else ""
                    val msg = ChatMessage(
                        sender = senderName,
                        text = text,
                        isMine = false,
                        transport = "$transport$rssiLabel",
                        timestamp = timeFmt.format(Date()),
                        status = "Odszyfrowano E2E (#$seq)"
                    )
                    synchronized(messageHistory) { messageHistory.add(msg) }
                    onChatUpdated?.invoke(msg)
                    pushTelemetry()
                }
            }
            res.startsWith("RELAY|") -> {
                lastRssi = rssi
                updateNotification("AETHER • ${gnssScheduler.powerMode.label} • Bufor DTN: ${engine.bufferCount()}")
                pushTelemetry()
            }
        }
    }

    private fun batteryLevelPct(): Int =
        batteryManager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY).coerceIn(0, 100)

    fun pushTelemetry() {
        onTelemetryUpdated?.invoke(
            RadioTelemetry(
                powerMode = gnssScheduler.powerMode,
                codedPhySupported = runCatching { bluetoothAdapter.isLeCodedPhySupported }.getOrDefault(false),
                gnssCalibrated = gnssScheduler.isGnssCalibrated(),
                relayBufferCount = engine.bufferCount(),
                relayedOutCount = relayedOutCount,
                lastRssi = lastRssi,
                pairedPeerName = pairedPeerName
            )
        )
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(1001, buildNotification(text))
    }

    private fun buildNotification(text: String): Notification {
        val channelId = "aether_l0_radio"
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(channelId, "AETHER Off-Grid Radio", NotificationManager.IMPORTANCE_LOW)
        )
        return NotificationCompat.Builder(this, channelId)
            .setContentTitle("AETHER Zero-Infrastructure")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setOngoing(true)
            .build()
    }
}
