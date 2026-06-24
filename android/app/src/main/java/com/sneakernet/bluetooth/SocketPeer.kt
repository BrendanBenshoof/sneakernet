package com.sneakernet.bluetooth

import android.bluetooth.BluetoothSocket
import com.sneakernet.engine.mobile.BluetoothPeer
import java.io.IOException

/**
 * SocketPeer wraps a connected [BluetoothSocket] and implements the Go
 * [BluetoothPeer] interface so it can be passed to Engine.runBluetoothSession.
 *
 * Read blocks until data is available — that matches the stream semantics
 * the Go session protocol expects (io.ReadFull on the Go side).
 */
class SocketPeer(private val socket: BluetoothSocket) : BluetoothPeer {

    private val inputStream = socket.inputStream
    private val outputStream = socket.outputStream

    /**
     * Reads up to [b].size bytes into [b]. Returns the number of bytes read.
     * Returns 0 if the stream is at EOF (remote side closed the connection).
     *
     * gomobile maps Go's `(int, error)` to a `long` return with Java exception.
     */
    @Throws(IOException::class)
    override fun read(b: ByteArray): Long {
        val n = inputStream.read(b)
        return if (n < 0) 0L else n.toLong()
    }

    @Throws(IOException::class)
    override fun write(b: ByteArray) {
        outputStream.write(b)
        outputStream.flush()
    }

    @Throws(IOException::class)
    override fun close() {
        socket.close()
    }
}
