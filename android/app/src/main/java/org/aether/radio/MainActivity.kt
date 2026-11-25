package org.aether.radio

import android.Manifest
import android.app.AlertDialog
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.*
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView

/**
 * AETHER v0.4.0 — Ultra-Lightweight, True-Black OLED Modern Off-Grid Messenger UI.
 *
 * Design principles:
 *  - Pure #000000 OLED canvas (pixels physically OFF -> minimal screen power)
 *  - Zero heavy UI frameworks -> < 3 MB APK, instant launch, minimal RAM
 *  - Auto-shifts radio to ECO_SLEEP (0.8% duty cycle) when minimized, ACTIVE_CHAT while open
 *  - 5-second offline pairing modal + dual transport (BLE 5.0 Coded PHY & Ultrasonic 19.5 kHz)
 */
class MainActivity : AppCompatActivity() {

    private var bleService: AetherBleService? = null
    private lateinit var statusLine: TextView
    private lateinit var telemetryPills: TextView
    private lateinit var powerBtn: Button
    private lateinit var recycler: RecyclerView
    private lateinit var inputBox: EditText
    private lateinit var adapter: ChatAdapter
    private var manualEcoLock = false

    private val permLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { startAndBindService() }

    private val conn = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            val svc = (service as AetherBleService.LocalBinder).getService()
            bleService = svc
            adapter.replaceAll(svc.messageHistory)
            svc.onChatUpdated = { msg ->
                runOnUiThread {
                    adapter.addMessage(msg)
                    recycler.scrollToPosition((adapter.itemCount - 1).coerceAtLeast(0))
                }
            }
            svc.onTelemetryUpdated = { tel ->
                runOnUiThread { renderTelemetry(tel) }
            }
            svc.onStatusToast = { msg ->
                runOnUiThread { Toast.makeText(this@MainActivity, msg, Toast.LENGTH_SHORT).show() }
            }
            if (!manualEcoLock) svc.setPowerMode(PowerMode.ACTIVE_CHAT)
            svc.pushTelemetry()
            if (!svc.isPaired()) showPairingDialog()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            bleService = null
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(buildOledUi())
        requestRadioPermissions()
    }

    override fun onResume() {
        super.onResume()
        if (!manualEcoLock) bleService?.setPowerMode(PowerMode.ACTIVE_CHAT)
    }

    override fun onPause() {
        super.onPause()
        // Drop to ultra-low-power ECO_SLEEP (0.8% duty cycle) immediately when screen turns off!
        bleService?.setPowerMode(PowerMode.ECO_SLEEP)
    }

    private fun buildOledUi(): View {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#000000"))
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
        }

        // --- TOP HEADER BAR (OLED Dark Surface) ---
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setBackgroundColor(Color.parseColor("#090D16"))
            setPadding(dp(16), dp(14), dp(12), dp(12))
        }

        val titleCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        val title = TextView(this).apply {
            text = "AETHER"
            textSize = 18f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.parseColor("#F8FAFC"))
            letterSpacing = 0.08f
        }
        statusLine = TextView(this).apply {
            text = "Zero-Internet • Inicjalizacja..."
            textSize = 11.5f
            setTextColor(Color.parseColor("#10B981"))
        }
        titleCol.addView(title)
        titleCol.addView(statusLine)

        powerBtn = makePillButton("ECO", "#0F172A", "#38BDF8") {
            manualEcoLock = !manualEcoLock
            val next = if (manualEcoLock) PowerMode.ECO_SLEEP else PowerMode.ACTIVE_CHAT
            bleService?.setPowerMode(next)
            Toast.makeText(this, "Tryb zasilania: ${next.label}", Toast.LENGTH_SHORT).show()
        }
        val pairBtn = makePillButton("PARUJ", "#1E293B", "#F8FAFC") { showPairingDialog() }

        header.addView(titleCol)
        header.addView(powerBtn)
        header.addView(spaceX(6))
        header.addView(pairBtn)
        root.addView(header)

        // --- TELEMETRY STRIP (BLE Coded PHY / GNSS / DTN Courier Buffer) ---
        telemetryPills = TextView(this).apply {
            text = "BLE 5.0 • GNSS • Bufor Kuriera DTN: 0"
            textSize = 10.5f
            setTextColor(Color.parseColor("#94A3B8"))
            setBackgroundColor(Color.parseColor("#05080F"))
            setPadding(dp(16), dp(6), dp(16), dp(6))
        }
        root.addView(telemetryPills)

        // --- MESSAGE STREAM ---
        adapter = ChatAdapter()
        recycler = RecyclerView(this).apply {
            layoutManager = LinearLayoutManager(this@MainActivity).apply { stackFromEnd = true }
            adapter = this@MainActivity.adapter
            setPadding(dp(12), dp(8), dp(12), dp(8))
            clipToPadding = false
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f)
        }
        root.addView(recycler)

        // --- AIR-GAP ULTRASONIC QUICK BAR ---
        val airGapBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setBackgroundColor(Color.parseColor("#070B12"))
            setPadding(dp(12), dp(6), dp(12), dp(6))
        }
        val btnAudioTx = makePillButton("🔊 Wyślij 19.5 kHz", "#172554", "#93C5FD") {
            val txt = inputBox.text.toString().trim()
            if (txt.isEmpty()) {
                Toast.makeText(this, "Wpisz najpierw wiadomość poniżej", Toast.LENGTH_SHORT).show()
            } else {
                inputBox.text.clear()
                bleService?.sendTextViaUltrasonic(txt)
            }
        }
        val btnAudioRx = makePillButton("🎙 Nasłuch 19.5 kHz", "#14532D", "#86EFAC") {
            bleService?.listenUltrasonic()
        }
        airGapBar.addView(btnAudioTx)
        airGapBar.addView(spaceX(8))
        airGapBar.addView(btnAudioRx)
        root.addView(airGapBar)

        // --- COMPOSER BAR ---
        val composer = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setBackgroundColor(Color.parseColor("#0B1120"))
            setPadding(dp(10), dp(8), dp(10), dp(10))
        }
        inputBox = EditText(this).apply {
            hint = "Napisz bez internetu (maks. 182 B)..."
            setHintTextColor(Color.parseColor("#64748B"))
            setTextColor(Color.parseColor("#F8FAFC"))
            textSize = 14.5f
            background = roundedBg("#111827", "#1E293B", 20f)
            setPadding(dp(14), dp(10), dp(14), dp(10))
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        val sendBtn = makePillButton("WYŚLIJ", "#1F6FEB", "#FFFFFF") {
            val txt = inputBox.text.toString().trim()
            if (txt.isNotEmpty()) {
                inputBox.text.clear()
                bleService?.sendTextViaBle(txt, urgent = false)
            }
        }
        composer.addView(inputBox)
        composer.addView(spaceX(8))
        composer.addView(sendBtn)
        root.addView(composer)

        return root
    }

    private fun renderTelemetry(tel: RadioTelemetry) {
        val peer = tel.pairedPeerName ?: "Niesparowany (kliknij PARUJ)"
        statusLine.text = "$peer • ${tel.powerMode.label}"
        val phy = if (tel.codedPhySupported) "Coded PHY S=8" else "BLE 1M"
        val gnss = if (tel.gnssCalibrated) "GNSS: LOCK" else "Zegar lokalny"
        val rssi = tel.lastRssi?.let { " • ${it} dBm" } ?: ""
        telemetryPills.text = "$phy • $gnss • Kurier DTN: ${tel.relayBufferCount} (przekazano ${tel.relayedOutCount})$rssi"
        powerBtn.text = if (manualEcoLock) "ECO ON" else "AUTO"
    }

    private fun showPairingDialog() {
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(16), dp(20), dp(8))
        }
        val etName = EditText(this).apply {
            hint = "Nazwa kontaktu (np. Żona / Mąż)"
            setText("Żona")
        }
        val etPass = EditText(this).apply {
            hint = "Wspólne hasło parowania offline"
            setText("AETHER-2026")
        }
        val roleSwitch = Switch(this).apply {
            text = "Ten telefon to Telefon A (Inicjator) — na drugim ODZNACZ!"
            isChecked = true
            setPadding(0, dp(10), 0, dp(4))
        }
        layout.addView(etName)
        layout.addView(etPass)
        layout.addView(roleSwitch)

        AlertDialog.Builder(this)
            .setTitle("Parowanie Offline (Zero Serwerów)")
            .setMessage("Wpiszcie to samo hasło na obu telefonach. Na Twoim zostaw 'Telefon A' włączone, na telefonie żony wyłącz.")
            .setView(layout)
            .setPositiveButton("Sparuj E2E") { _, _ ->
                val name = etName.text.toString().ifBlank { "Kontakt" }
                val pass = etPass.text.toString().ifBlank { "AETHER-2026" }
                bleService?.configurePairing(name, pass, roleSwitch.isChecked)
            }
            .setNegativeButton("Później", null)
            .show()
    }

    private fun requestRadioPermissions() {
        val perms = mutableListOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.RECORD_AUDIO)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            perms += Manifest.permission.BLUETOOTH_ADVERTISE
            perms += Manifest.permission.BLUETOOTH_SCAN
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            perms += Manifest.permission.POST_NOTIFICATIONS
        }
        permLauncher.launch(perms.toTypedArray())
    }

    private fun startAndBindService() {
        val intent = Intent(this, AetherBleService::class.java)
        ContextCompat.startForegroundService(this, intent)
        bindService(intent, conn, Context.BIND_AUTO_CREATE)
    }

    override fun onDestroy() {
        bleService?.onChatUpdated = null
        bleService?.onTelemetryUpdated = null
        bleService?.onStatusToast = null
        runCatching { unbindService(conn) }
        super.onDestroy()
    }

    // --- UI Helpers ---
    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()
    private fun spaceX(v: Int) = View(this).apply { layoutParams = LinearLayout.LayoutParams(dp(v), 1) }

    private fun roundedBg(fillHex: String, strokeHex: String, radiusDp: Float) = GradientDrawable().apply {
        setColor(Color.parseColor(fillHex))
        setStroke(dp(1), Color.parseColor(strokeHex))
        cornerRadius = radiusDp * resources.displayMetrics.density
    }

    private fun makePillButton(label: String, bgHex: String, fgHex: String, onClick: () -> Unit): Button =
        Button(this).apply {
            text = label
            textSize = 11.5f
            isAllCaps = false
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.parseColor(fgHex))
            background = roundedBg(bgHex, bgHex, 16f)
            minHeight = 0
            minimumHeight = 0
            minWidth = 0
            minimumWidth = 0
            setPadding(dp(12), dp(7), dp(12), dp(7))
            setOnClickListener { onClick() }
        }

    // --- Ultra-Lightweight Chat Bubble Adapter ---
    inner class ChatAdapter : RecyclerView.Adapter<ChatAdapter.VH>() {
        private val items = ArrayList<ChatMessage>()

        fun replaceAll(list: List<ChatMessage>) {
            items.clear()
            items.addAll(list)
            notifyDataSetChanged()
        }

        fun addMessage(m: ChatMessage) {
            items.add(m)
            notifyItemInserted(items.size - 1)
        }

        inner class VH(val container: LinearLayout, val bubble: LinearLayout, val body: TextView, val meta: TextView) :
            RecyclerView.ViewHolder(container)

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
            val container = LinearLayout(parent.context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = RecyclerView.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply { setMargins(0, dp(4), 0, dp(4)) }
            }
            val bubble = LinearLayout(parent.context).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(14), dp(9), dp(14), dp(8))
            }
            val body = TextView(parent.context).apply {
                textSize = 15f
                setTextColor(Color.parseColor("#F8FAFC"))
            }
            val meta = TextView(parent.context).apply {
                textSize = 10.5f
                setTextColor(Color.parseColor("#94A3B8"))
                setPadding(0, dp(3), 0, 0)
            }
            bubble.addView(body)
            bubble.addView(meta)
            container.addView(bubble)
            return VH(container, bubble, body, meta)
        }

        override fun onBindViewHolder(holder: VH, position: Int) {
            val m = items[position]
            holder.container.gravity = if (m.isMine) Gravity.END else Gravity.START
            holder.bubble.background = if (m.isMine) {
                roundedBg("#1D4ED8", "#2563EB", 16f)
            } else {
                roundedBg("#111827", "#1F2937", 16f)
            }
            holder.body.text = m.text
            holder.meta.text = "${m.sender} • ${m.timestamp} • ${m.transport} • ${m.status}"
        }

        override fun getItemCount(): Int = items.size
    }
}
