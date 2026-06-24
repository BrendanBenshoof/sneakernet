package com.sneakernet.sync

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Starts [SneakernetSyncService] when the device finishes booting so that
 * sync continues without requiring the user to open the app.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        context.startForegroundService(Intent(context, SneakernetSyncService::class.java))
    }
}
