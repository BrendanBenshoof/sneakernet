package com.sneakernet.sync

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothSocket
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.IBinder
import android.os.ParcelUuid
import android.util.Log
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import com.sneakernet.R
import com.sneakernet.SneakernetApp
import com.sneakernet.bluetooth.SocketPeer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Persistent foreground service that keeps all sneakernet sync running:
 *  - Relay peer sync (HTTP)
 *  - LAN discovery + LAN relay server
 *  - Bluetooth block exchange (RFCOMM + BLE discovery)
 *
 * Started on boot via [BootReceiver] and from [com.sneakernet.SneakernetApp].
 * Send [ACTION_ENABLE_BT] to activate Bluetooth after runtime permissions are granted.
 */
class SneakernetSyncService : Service() {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private var btStarted = false
    private var leAdvertiser: BluetoothLeAdvertiser? = null
    private var leScanner: BluetoothLeScanner? = null

    // Active peer addresses prevent duplicate concurrent sessions.
    private val activePeers = ConcurrentHashMap<String, Unit>()
    // Per-address cooldown prevents immediately reconnecting after a session ends.
    private val sessionCooldowns = ConcurrentHashMap<String, Long>()

    private val engine get() = (application as SneakernetApp).engine

    // --- Lifecycle ---

    override fun onCreate() {
        super.onCreate()
        // Start with dataSync only — connectedDevice requires BT runtime permissions
        // which may not be granted yet on first launch.
        startForeground(
            NOTIFICATION_ID,
            buildNotification(),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
        )
        startSyncAndLan()
        if (btPermissionsGranted()) startBluetooth()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_ENABLE_BT) startBluetooth()
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        scope.cancel()
        stopBle()
        super.onDestroy()
    }

    // --- Relay + LAN ---

    private fun startSyncAndLan() {
        val eng = engine ?: return
        eng.startSync(SYNC_INTERVAL_SECS)
        eng.startLANDiscovery(LAN_SCAN_INTERVAL_SECS)
        try {
            eng.startLANServer()
        } catch (e: Exception) {
            Log.w(TAG, "LAN server failed to bind: ${e.message}")
        }
    }

    // --- Bluetooth ---

    private fun startBluetooth() {
        if (btStarted) return
        btStarted = true
        // Upgrade foreground type to include connectedDevice now that BT permissions
        // are confirmed — the system enforces this at startForeground time.
        startForeground(
            NOTIFICATION_ID,
            buildNotification(),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC or
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE,
        )
        startRfcommServer()
        startBle()
        Log.i(TAG, "Bluetooth sync started")
    }

    private fun startRfcommServer() {
        val adapter = (getSystemService(BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter ?: return
        scope.launch {
            try {
                val serverSocket = adapter.listenUsingRfcommWithServiceRecord("sneakernet", SERVICE_UUID)
                Log.i(TAG, "RFCOMM listening")
                while (isActive) {
                    val socket = withContext(Dispatchers.IO) { serverSocket.accept() }
                    Log.i(TAG, "inbound BT from ${socket.remoteDevice.address}")
                    launch { runSession(socket) }
                }
                serverSocket.close()
            } catch (e: IOException) {
                if (isActive) Log.e(TAG, "RFCOMM server error: ${e.message}")
            }
        }
    }

    private fun startBle() {
        val mgr = getSystemService(BLUETOOTH_SERVICE) as? BluetoothManager ?: return
        val adapter = mgr.adapter ?: return
        if (!hasPermission(Manifest.permission.BLUETOOTH_ADVERTISE)) return

        leAdvertiser = adapter.bluetoothLeAdvertiser
        leScanner = adapter.bluetoothLeScanner

        leAdvertiser?.startAdvertising(
            AdvertiseSettings.Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_POWER)
                .setConnectable(false)
                .setTimeout(0)
                .build(),
            AdvertiseData.Builder()
                .addServiceUuid(ParcelUuid(SERVICE_UUID))
                .setIncludeDeviceName(false)
                .build(),
            advertiseCallback,
        )

        if (!hasPermission(Manifest.permission.BLUETOOTH_SCAN)) return
        leScanner?.startScan(
            listOf(ScanFilter.Builder().setServiceUuid(ParcelUuid(SERVICE_UUID)).build()),
            ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_POWER).build(),
            scanCallback,
        )
        Log.d(TAG, "BLE advertising and scanning")
    }

    private fun stopBle() {
        if (hasPermission(Manifest.permission.BLUETOOTH_ADVERTISE))
            leAdvertiser?.stopAdvertising(advertiseCallback)
        if (hasPermission(Manifest.permission.BLUETOOTH_SCAN))
            leScanner?.stopScan(scanCallback)
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartFailure(errorCode: Int) {
            Log.w(TAG, "BLE advertise failed: $errorCode")
        }
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val device = result.device
            val addr = device.address
            if (activePeers.containsKey(addr)) return
            if (System.currentTimeMillis() < (sessionCooldowns[addr] ?: 0L)) return
            scope.launch { connectToPeer(device) }
        }
    }

    private suspend fun connectToPeer(device: BluetoothDevice) {
        val addr = device.address
        // putIfAbsent returns null when the key was absent (we got the slot).
        if (activePeers.putIfAbsent(addr, Unit) != null) return
        try {
            val socket = withContext(Dispatchers.IO) {
                device.createRfcommSocketToServiceRecord(SERVICE_UUID).also { it.connect() }
            }
            Log.i(TAG, "outbound BT to $addr")
            runSession(socket)
        } catch (e: IOException) {
            Log.d(TAG, "connect $addr: ${e.message}")
            activePeers.remove(addr)
        }
    }

    private suspend fun runSession(socket: BluetoothSocket) {
        val addr = socket.remoteDevice.address
        activePeers[addr] = Unit
        try {
            val eng = engine ?: run { socket.close(); return }
            withContext(Dispatchers.IO) { eng.runBluetoothSession(SocketPeer(socket)) }
            Log.i(TAG, "BT session complete with $addr")
        } catch (e: Exception) {
            Log.e(TAG, "BT session error $addr: ${e.message}")
        } finally {
            activePeers.remove(addr)
            sessionCooldowns[addr] = System.currentTimeMillis() + SESSION_COOLDOWN_MS
            runCatching { socket.close() }
        }
    }

    // --- Helpers ---

    private fun btPermissionsGranted() = BT_PERMISSIONS.all { hasPermission(it) }

    private fun hasPermission(p: String) =
        ActivityCompat.checkSelfPermission(this, p) == PackageManager.PERMISSION_GRANTED

    private fun buildNotification(): Notification {
        val channelId = "sneakernet_sync"
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(
                channelId,
                getString(R.string.notif_channel_sync),
                NotificationManager.IMPORTANCE_LOW,
            )
        )
        return NotificationCompat.Builder(this, channelId)
            .setContentTitle(getString(R.string.notif_title_sync))
            .setContentText(getString(R.string.notif_text_sync))
            .setSmallIcon(R.drawable.ic_sync)
            .setOngoing(true)
            .build()
    }

    companion object {
        /** Send this action to enable Bluetooth after runtime permissions are granted. */
        const val ACTION_ENABLE_BT = "com.sneakernet.ENABLE_BT"

        val BT_PERMISSIONS = arrayOf(
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_ADVERTISE,
        )

        val SERVICE_UUID: UUID = UUID.fromString("b533e7a1-4c6d-4f89-aeb2-73c97a8d1e40")

        private const val NOTIFICATION_ID = 1001
        private const val SESSION_COOLDOWN_MS = 60_000L
        private const val SYNC_INTERVAL_SECS = 300L
        private const val LAN_SCAN_INTERVAL_SECS = 300L
        private const val TAG = "SneakernetSyncService"
    }
}
