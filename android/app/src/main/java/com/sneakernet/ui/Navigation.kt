package com.sneakernet.ui

import androidx.compose.runtime.*
import androidx.compose.ui.platform.LocalContext
import com.sneakernet.storage.StoragePrefs
import com.sneakernet.ui.screens.SetupScreen
import com.sneakernet.ui.screens.WebViewScreen

@Composable
fun SneakernetNavHost() {
    val context = LocalContext.current
    val prefs = remember { StoragePrefs(context) }
    var setupComplete by remember { mutableStateOf(prefs.isSetupComplete) }

    if (!setupComplete) {
        SetupScreen(onComplete = { setupComplete = true })
    } else {
        WebViewScreen()
    }
}
