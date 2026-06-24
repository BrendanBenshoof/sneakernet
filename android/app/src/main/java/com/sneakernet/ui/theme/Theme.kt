package com.sneakernet.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val ColorScheme = darkColorScheme(
    primary = Color(0xFF76D7C4),
    secondary = Color(0xFF48C9B0),
    background = Color(0xFF1A1A2E),
    surface = Color(0xFF16213E),
    onPrimary = Color(0xFF000000),
    onBackground = Color(0xFFE0E0E0),
    onSurface = Color(0xFFE0E0E0),
)

@Composable
fun SneakernetTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = ColorScheme,
        content = content,
    )
}
