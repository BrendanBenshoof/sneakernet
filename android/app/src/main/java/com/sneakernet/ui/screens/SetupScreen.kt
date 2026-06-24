package com.sneakernet.ui.screens

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bluetooth
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.sneakernet.SneakernetApp
import com.sneakernet.sync.SneakernetSyncService
import com.sneakernet.storage.StorageChecker
import com.sneakernet.storage.StoragePrefs

/**
 * First-run wizard: two pages (Permissions → Storage budget), then done.
 * [onComplete] is called once the user has finished setup with the chosen limit.
 */
@Composable
fun SetupScreen(onComplete: () -> Unit) {
    var page by remember { mutableIntStateOf(0) }

    AnimatedContent(targetState = page, label = "setup_page") { p ->
        when (p) {
            0 -> PermissionsPage(onContinue = { page = 1 })
            1 -> StorageBudgetPage(onComplete = onComplete)
        }
    }
}

// ─── Page 1: Permissions ──────────────────────────────────────────────────────

@Composable
private fun PermissionsPage(onContinue: () -> Unit) {
    val context = LocalContext.current

    fun allGranted() = SneakernetSyncService.BT_PERMISSIONS.all {
        ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED
    }

    var granted by remember { mutableStateOf(allGranted()) }

    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { results ->
        granted = results.values.all { it }
        if (granted) {
            context.startForegroundService(
                Intent(context, SneakernetSyncService::class.java)
                    .setAction(SneakernetSyncService.ACTION_ENABLE_BT)
            )
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 40.dp),
        verticalArrangement = Arrangement.spacedBy(24.dp),
    ) {
        SetupHeader(
            step = "1 of 2",
            title = "Bluetooth access",
            icon = Icons.Default.Bluetooth,
        )

        Text(
            "Sneakernet exchanges messages between nearby devices over Bluetooth, " +
            "with no internet required. This is the core of how it works.",
            style = MaterialTheme.typography.bodyLarge,
        )

        PermissionItem(
            name = "Connect to devices",
            reason = "Needed to open a data channel with a nearby sneakernet peer " +
                     "once they're discovered.",
        )
        PermissionItem(
            name = "Scan for devices",
            reason = "Lets the app find nearby peers advertising the sneakernet " +
                     "service. Only the sneakernet UUID is searched for — location " +
                     "data is never collected.",
        )
        PermissionItem(
            name = "Advertise",
            reason = "Makes this device visible to nearby peers so they can " +
                     "initiate an exchange. The ad contains no personal data.",
        )

        if (granted) {
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)) {
                Text(
                    "Bluetooth access granted.",
                    modifier = Modifier.padding(12.dp),
                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                )
            }
            Button(onClick = onContinue, modifier = Modifier.fillMaxWidth()) {
                Text("Continue")
            }
        } else {
            Button(
                onClick = { launcher.launch(SneakernetSyncService.BT_PERMISSIONS) },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Grant Bluetooth access")
            }
            TextButton(onClick = onContinue, modifier = Modifier.fillMaxWidth()) {
                Text("Skip for now (Bluetooth sync will be unavailable)")
            }
        }
    }
}

@Composable
private fun PermissionItem(name: String, reason: String) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(name, fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodyMedium)
        Text(reason, style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f))
    }
}

// ─── Page 2: Storage budget ───────────────────────────────────────────────────

@Composable
private fun StorageBudgetPage(onComplete: () -> Unit) {
    val context = LocalContext.current
    val prefs = remember { StoragePrefs(context) }
    val filesDir = context.filesDir

    val steps = StoragePrefs.STORAGE_STEPS_BYTES
    var stepIndex by remember { mutableIntStateOf(StoragePrefs.DEFAULT_STEP_INDEX) }
    val chosenBytes = steps[stepIndex]

    val totalBytes = remember { StorageChecker.getTotalBytes(filesDir) }
    val freeBytes  = remember { StorageChecker.getFreeBytes(filesDir) }
    val tooLarge   = chosenBytes > freeBytes && freeBytes > 0

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 40.dp),
        verticalArrangement = Arrangement.spacedBy(24.dp),
    ) {
        SetupHeader(
            step = "2 of 2",
            title = "Storage budget",
            icon = Icons.Default.Storage,
        )

        Text(
            "Sneakernet stores encrypted message blocks on your device so they can " +
            "be relayed to others, even offline. Choose a maximum. The app will " +
            "never exceed this — older relay blocks are deleted automatically to " +
            "stay within budget.",
            style = MaterialTheme.typography.bodyLarge,
        )

        // Disk context
        if (totalBytes > 0) {
            StorageBar(
                label = "Device storage",
                usedBytes = totalBytes - freeBytes,
                totalBytes = totalBytes,
                highlightBytes = chosenBytes,
            )
        }

        // Chosen limit display
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Reserved for Sneakernet", style = MaterialTheme.typography.labelLarge)
                    Text(
                        StoragePrefs.formatBytes(chosenBytes),
                        style = MaterialTheme.typography.titleLarge,
                        color = MaterialTheme.colorScheme.primary,
                        fontWeight = FontWeight.Bold,
                    )
                }

                Slider(
                    value = stepIndex.toFloat(),
                    onValueChange = { stepIndex = it.toInt() },
                    steps = steps.size - 2,  // interior steps only
                    valueRange = 0f..(steps.size - 1).toFloat(),
                )

                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(StoragePrefs.formatBytes(steps.first()),
                        style = MaterialTheme.typography.labelSmall)
                    Text(StoragePrefs.formatBytes(steps.last()),
                        style = MaterialTheme.typography.labelSmall)
                }
            }
        }

        // Reservation breakdown
        BudgetBreakdown(chosenBytes)

        // Warning if too large
        if (tooLarge) {
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.errorContainer
                )
            ) {
                Text(
                    "Your device only has ${StoragePrefs.formatBytes(freeBytes)} free. " +
                    "Choose a smaller budget or free up space first.",
                    modifier = Modifier.padding(12.dp),
                    color = MaterialTheme.colorScheme.onErrorContainer,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }

        Button(
            onClick = {
                prefs.storageLimitBytes = chosenBytes
                prefs.isSetupComplete = true

                // Apply to the running engine. ConfigureStorage also creates and
                // sizes the .storage_quota balloon file so the OS storage reporter
                // shows the full budget immediately (no Android SDK needed).
                (context.applicationContext as? SneakernetApp)?.engine?.configureStorage(
                    chosenBytes,
                    prefs.physicalReserveBytes,
                    prefs.bluetoothReserveBytes,
                )

                onComplete()
            },
            enabled = !tooLarge,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Reserve ${StoragePrefs.formatBytes(chosenBytes)} and continue")
        }
    }
}

@Composable
private fun BudgetBreakdown(totalBytes: Long) {
    val physical  = totalBytes / 4
    val bluetooth = totalBytes / 4
    val relay     = totalBytes - physical - bluetooth

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("How it's divided", style = MaterialTheme.typography.labelLarge)
            Spacer(Modifier.height(2.dp))
            BudgetLine("Your messages (always kept)", physical, totalBytes)
            BudgetLine("Bluetooth peer blocks (kept longer)", bluetooth, totalBytes)
            BudgetLine("Relay blocks (evicted first when full)", relay, totalBytes)
        }
    }
}

@Composable
private fun BudgetLine(label: String, bytes: Long, total: Long) {
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.weight(1f))
        Text(
            StoragePrefs.formatBytes(bytes),
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Medium,
        )
    }
}

// ─── Shared components ────────────────────────────────────────────────────────

@Composable
private fun SetupHeader(step: String, title: String, icon: ImageVector) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(step, style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.primary)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(28.dp))
            Text(title, style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold)
        }
    }
}

/**
 * Horizontal bar showing [usedBytes] out of [totalBytes], with [highlightBytes]
 * shown as the proposed Sneakernet reservation.
 */
@Composable
private fun StorageBar(
    label: String,
    usedBytes: Long,
    totalBytes: Long,
    highlightBytes: Long,
) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(label, style = MaterialTheme.typography.labelMedium)
            Text(
                "${StoragePrefs.formatBytes(usedBytes)} used of " +
                StoragePrefs.formatBytes(totalBytes),
                style = MaterialTheme.typography.labelMedium,
            )
        }
        // Stacked progress: used (grey) + sneakernet budget (primary)
        Box(
            Modifier
                .fillMaxWidth()
                .height(12.dp)
        ) {
            LinearProgressIndicator(
                progress = { usedBytes.toFloat() / totalBytes },
                modifier = Modifier.fillMaxSize(),
                color = MaterialTheme.colorScheme.outline,
                trackColor = MaterialTheme.colorScheme.surfaceVariant,
            )
            LinearProgressIndicator(
                progress = { highlightBytes.toFloat() / totalBytes },
                modifier = Modifier.fillMaxSize(),
                color = MaterialTheme.colorScheme.primary.copy(alpha = 0.5f),
                trackColor = androidx.compose.ui.graphics.Color.Transparent,
            )
        }
        Text(
            "Sneakernet would use up to ${StoragePrefs.formatBytes(highlightBytes)}",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.primary,
        )
    }
}
