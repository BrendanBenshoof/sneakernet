package com.sneakernet

import android.app.Application
import android.content.Intent
import android.util.Log
import com.sneakernet.engine.mobile.Engine
import com.sneakernet.storage.StoragePrefs
import com.sneakernet.sync.SneakernetSyncService

class SneakernetApp : Application() {

    var engine: Engine? = null
        private set

    override fun onCreate() {
        super.onCreate()
        initEngine()
        // Keep sync running for the lifetime of the process. The service is also
        // started by BootReceiver after reboot; startForegroundService is idempotent.
        startForegroundService(Intent(this, SneakernetSyncService::class.java))
    }

    private fun initEngine() {
        val dataDir = filesDir.absolutePath
        val keystorePath = "$dataDir/keystore.json"
        val prefs = StoragePrefs(this)

        try {
            val eng = Engine(dataDir)

            if (prefs.storageLimitBytes > 0) {
                eng.configureStorage(
                    prefs.storageLimitBytes,
                    prefs.physicalReserveBytes,
                    prefs.bluetoothReserveBytes,
                )
                Log.i(TAG, "storage limit: ${StoragePrefs.formatBytes(prefs.storageLimitBytes)}")
            }

            eng.startAPIServer(API_ADDR, keystorePath)
            engine = eng
            Log.i(TAG, "sneakernet engine started on $API_ADDR")
        } catch (e: Exception) {
            Log.e(TAG, "failed to start engine: ${e.message}", e)
        }
    }

    override fun onTerminate() {
        super.onTerminate()
        try {
            engine?.close()
        } catch (e: Exception) {
            Log.w(TAG, "engine close: ${e.message}")
        }
    }

    companion object {
        const val API_ADDR     = "127.0.0.1:8080"
        const val API_BASE_URL = "http://$API_ADDR/"
        private const val TAG  = "SneakernetApp"
    }
}
