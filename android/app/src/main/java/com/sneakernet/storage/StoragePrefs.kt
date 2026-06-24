package com.sneakernet.storage

import android.content.Context

/**
 * Persists the user's storage configuration choices across restarts.
 * All values here are the user's explicit decisions — never change them silently.
 */
class StoragePrefs(context: Context) {

    private val prefs = context.getSharedPreferences("sneakernet_storage", Context.MODE_PRIVATE)

    /** Whether the first-run setup wizard has been completed. */
    var isSetupComplete: Boolean
        get() = prefs.getBoolean(KEY_SETUP_COMPLETE, false)
        set(v) = prefs.edit().putBoolean(KEY_SETUP_COMPLETE, v).apply()

    /**
     * The maximum blockstore size in bytes the user has agreed to.
     * 0 means the user hasn't set one yet (setup incomplete).
     */
    var storageLimitBytes: Long
        get() = prefs.getLong(KEY_STORAGE_LIMIT, 0L)
        set(v) = prefs.edit().putLong(KEY_STORAGE_LIMIT, v).apply()

    /**
     * Fraction of the limit reserved for locally-authored and BT-received blocks.
     * These blocks survive relay-block eviction longer.
     * Default: 25% of total limit.
     */
    val physicalReserveBytes: Long
        get() = storageLimitBytes / 4

    val bluetoothReserveBytes: Long
        get() = storageLimitBytes / 4

    companion object {
        private const val KEY_SETUP_COMPLETE = "setup_complete"
        private const val KEY_STORAGE_LIMIT  = "storage_limit_bytes"

        // Slider steps shown to the user during setup.
        val STORAGE_STEPS_BYTES = longArrayOf(
            64L  * MB,
            128L * MB,
            256L * MB,
            512L * MB,
            1L   * GB,
            2L   * GB,
            4L   * GB,
            8L   * GB,
        )

        val DEFAULT_STEP_INDEX = 4  // 1 GB
        val MIN_LIMIT_BYTES    = STORAGE_STEPS_BYTES.first()

        private const val MB = 1024L * 1024L
        private const val GB = 1024L * MB

        fun formatBytes(bytes: Long): String = when {
            bytes >= GB   -> "%.1f GB".format(bytes.toDouble() / GB)
            bytes >= MB   -> "%.0f MB".format(bytes.toDouble() / MB)
            else          -> "${bytes / 1024} KB"
        }
    }
}
