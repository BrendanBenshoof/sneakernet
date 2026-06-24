package com.sneakernet

import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import com.sneakernet.sync.SneakernetSyncService
import com.sneakernet.ui.SneakernetNavHost
import com.sneakernet.ui.theme.SneakernetTheme

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            SneakernetTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    SneakernetNavHost()
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // If BT permissions were granted since last launch, activate BT in the service.
        if (btPermissionsGranted()) {
            startForegroundService(
                Intent(this, SneakernetSyncService::class.java)
                    .setAction(SneakernetSyncService.ACTION_ENABLE_BT)
            )
        }
    }

    private fun btPermissionsGranted() = SneakernetSyncService.BT_PERMISSIONS.all {
        ContextCompat.checkSelfPermission(this, it) == PackageManager.PERMISSION_GRANTED
    }
}
