package com.sneakernet.storage

import android.os.StatFs
import android.content.Context
import android.os.storage.StorageManager
import java.io.File

/**
 * Thin wrapper over OS storage APIs — used during setup to show the user
 * how much space is available so they can choose a sensible budget.
 *
 * The actual storage reservation is handled by the Go engine's quota balloon
 * (a sparse `.storage_quota` file that keeps the visible footprint constant).
 * No Android-specific pre-allocation is needed here.
 */
object StorageChecker {

    /** Bytes that could realistically be allocated in the volume containing [dir]. */
    fun getAllocatableBytes(context: Context, dir: File): Long {
        return try {
            val mgr = context.getSystemService(StorageManager::class.java)
            mgr.getAllocatableBytes(mgr.getUuidForPath(dir))
        } catch (_: Exception) {
            getFreeBytes(dir) // fallback
        }
    }

    /** Total bytes on the volume containing [dir]. */
    fun getTotalBytes(dir: File): Long = runCatching { StatFs(dir.absolutePath).totalBytes }.getOrDefault(0L)

    /** Free bytes on the volume containing [dir]. */
    fun getFreeBytes(dir: File): Long = runCatching { StatFs(dir.absolutePath).availableBytes }.getOrDefault(0L)
}
