// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.util.Log
import android.os.SystemClock
import java.util.concurrent.atomic.AtomicLong
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executors

/**
 * Rolling file logger writing into the app's private files directory
 * (`filesDir/logs`, no permissions required), so field issues can be
 * diagnosed after the fact instead of relying on ephemeral logcat.
 *
 * Mirrors the Apple FileLogger design: a single current file (`vault.log`)
 * appended with O_APPEND semantics, rotated to one backup file
 * (`vault.prev.log`) once it exceeds [MAX_LOG_SIZE], so the lines just
 * before a disconnect or crash survive.
 *
 * All writes are serialized on a single background thread so logging never
 * blocks the caller (e.g. the VPN packet path or the main thread).
 */
object VaultFileLogger {
    private const val TAG = "VaultFileLogger"
    private const val MAX_LOG_SIZE = 1024 * 1024L
    private const val LOG_FILE_NAME = "vault.log"
    private const val PREV_LOG_FILE_NAME = "vault.prev.log"

    private val writerThread = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "vault-file-logger").apply { isDaemon = true }
    }
    private val timestampFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)

    @Volatile
    private var logFile: File? = null

    @Volatile
    private var prevLogFile: File? = null

    private var eventFile: File? = null
    private val eventSequence = AtomicLong()

    @Suppress("TooGenericExceptionCaught") // A logger must never crash the app.
    @Synchronized
    fun init(context: android.content.Context) {
        if (logFile != null) return
        try {
            val logsDir = File(context.filesDir, "logs")
            logsDir.mkdirs()
            logFile = File(logsDir, LOG_FILE_NAME)
            prevLogFile = File(logsDir, PREV_LOG_FILE_NAME)
            context.getExternalFilesDir(null)?.let { directory ->
                val events = File(directory, "logs")
                events.mkdirs()
                eventFile = File(events, "vpn-events.log")
            }
            log(Log.INFO, TAG, "File logger initialized at ${logFile?.absolutePath}")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to init file logger", e)
        }
    }

    /** Absolute path of the current log file, null before [init]. */
    val currentLogPath: String?
        get() = logFile?.absolutePath

    /**
     * Append a single line to the log file. Safe to call from any thread;
     * the actual write happens on the writer thread.
     */
    @Suppress("TooGenericExceptionCaught") // A logger must never crash the caller.
    fun log(priority: Int, tag: String, message: String, throwable: Throwable? = null) {
        val file = logFile ?: return
        val level = when (priority) {
            Log.VERBOSE -> "V"
            Log.DEBUG -> "D"
            Log.INFO -> "I"
            Log.WARN -> "W"
            Log.ERROR -> "E"
            else -> "?"
        }
        // Capture the time at the call site so lines reflect event order,
        // not writer-queue delay. Formatting happens on the writer thread
        // because SimpleDateFormat is not thread-safe.
        val timestamp = System.currentTimeMillis()
        val stackTrace = throwable?.let { Log.getStackTraceString(it) }
        writerThread.execute {
            try {
                val line = buildString {
                    append('[').append(timestampFormat.format(Date(timestamp))).append("] [")
                        .append(level).append('/').append(tag).append("] ")
                        .append(message).append('\n')
                    if (stackTrace != null) {
                        append(stackTrace)
                    }
                }
                rotateIfNeeded(file)
                // append=true maps to O_APPEND, so appends never overwrite
                // existing content even after a rotation race.
                FileOutputStream(file, true).use { it.write(line.toByteArray(Charsets.UTF_8)) }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to write log line", e)
            }
        }
    }

    /** Low-volume lifecycle events; app-scoped copy is readable with authorized ADB. */
    @Suppress("TooGenericExceptionCaught") // A logger must never crash the caller.
    fun event(tag: String, message: String) {
        val entry = "seq=${eventSequence.incrementAndGet()} elapsedMs=${SystemClock.elapsedRealtime()} " +
            "thread=${Thread.currentThread().name} [$tag] $message"
        log(Log.INFO, tag, entry)
        val file = eventFile ?: return
        writerThread.execute {
            try {
                if (file.length() > MAX_LOG_SIZE) {
                    val previous = File(file.parentFile, "vpn-events.prev.log")
                    previous.delete()
                    file.renameTo(previous)
                }
                file.appendText(entry + "\n")
            } catch (e: Exception) {
                Log.w(TAG, "Failed to write diagnostic event", e)
            }
        }
    }

    /** Queue UI reads/clears behind Kotlin writes; append-only native writes remain safe. */
    suspend fun readLogs(): String = queuedLogs(false)
    suspend fun clearAndRead(): String = queuedLogs(true)

    private suspend fun queuedLogs(clear: Boolean): String = kotlinx.coroutines.suspendCancellableCoroutine { continuation ->
        writerThread.execute {
            try {
                if (clear) {
                    logFile?.let { FileOutputStream(it, false).use { stream -> stream.flush() } }
                    prevLogFile?.delete()
                }
                val content = listOfNotNull(prevLogFile, logFile).filter { it.exists() }
                    .joinToString("\n") { it.readText() }
                if (continuation.isActive) continuation.resumeWith(Result.success(content))
            } catch (error: java.io.IOException) {
                if (continuation.isActive) continuation.resumeWith(Result.failure(error))
            }
        }
    }

    private fun rotateIfNeeded(file: File) {
        val prev = prevLogFile ?: return
        if (file.exists() && file.length() > MAX_LOG_SIZE) {
            prev.delete()
            if (!file.renameTo(prev)) {
                Log.w(TAG, "Log rotation failed")
            }
        }
    }
}
