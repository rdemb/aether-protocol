package org.aether.radio

import android.annotation.SuppressLint
import android.content.Context
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.os.Looper
import android.os.SystemClock
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Adaptive Power-Saving GNSS UTC Clock & Slot Scheduler (AETHER v0.4.0).
 *
 * Dynamically scales radio duty cycle based on user activity:
 *  - ECO_SLEEP (screen off / background): 80 ms every 10,000 ms (0.8% duty cycle) -> ultra-low battery!
 *  - STANDARD_DTN (walking / courier):   180 ms every  5,000 ms (3.6% duty cycle)
 *  - ACTIVE_CHAT (app open on screen):   260 ms every  2,500 ms (fast interactive chat delivery)
 */
enum class PowerMode(val label: String, val periodMs: Long, val activeWindowMs: Long) {
    ECO_SLEEP("ECO (0.8%)", 10_000L, 80L),
    STANDARD_DTN("DTN (3.6%)", 5_000L, 180L),
    ACTIVE_CHAT("CZAT (Szybki)", 2_500L, 260L),
}

class GnssSlotScheduler(context: Context) {

    companion object {
        const val GNSS_RESYNC_INTERVAL_MS = 15 * 60 * 1000L
    }

    private val locationManager = context.getSystemService(Context.LOCATION_SERVICE) as LocationManager
    private val utcOffsetMs = AtomicLong(System.currentTimeMillis() - SystemClock.elapsedRealtime())
    private val gnssLocked = AtomicBoolean(false)

    @Volatile
    var powerMode: PowerMode = PowerMode.ACTIVE_CHAT

    private val listener = LocationListener { loc: Location ->
        if (loc.time > 1_700_000_000_000L) {
            utcOffsetMs.set(loc.time - SystemClock.elapsedRealtime())
            gnssLocked.set(true)
        }
    }

    @SuppressLint("MissingPermission")
    fun startPassiveCalibration() {
        runCatching {
            val last = locationManager.getLastKnownLocation(LocationManager.PASSIVE_PROVIDER)
                ?: locationManager.getLastKnownLocation(LocationManager.GPS_PROVIDER)
            if (last != null && last.time > 1_700_000_000_000L) {
                utcOffsetMs.set(last.time - SystemClock.elapsedRealtime())
                gnssLocked.set(true)
            }
            if (locationManager.isProviderEnabled(LocationManager.PASSIVE_PROVIDER)) {
                locationManager.requestLocationUpdates(
                    LocationManager.PASSIVE_PROVIDER,
                    GNSS_RESYNC_INTERVAL_MS,
                    0f,
                    listener,
                    Looper.getMainLooper()
                )
            }
        }
    }

    fun stopCalibration() {
        runCatching { locationManager.removeUpdates(listener) }
    }

    fun isGnssCalibrated(): Boolean = gnssLocked.get()
    fun currentUtcMs(): Long = SystemClock.elapsedRealtime() + utcOffsetMs.get()
    fun currentGnssEpochHour(): Long = currentUtcMs() / 3_600_000L

    fun delayToNextSlotMs(): Long {
        val period = powerMode.periodMs
        val mod = currentUtcMs() % period
        val wait = period - mod
        return if (wait < 15L) wait + period else wait
    }
}
