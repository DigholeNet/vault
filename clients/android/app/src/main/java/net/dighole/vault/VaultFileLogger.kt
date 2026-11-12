// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.os.SystemClock
import android.util.Log
import net.dighole.vaultcore.uniffi.appendSharedLog
import net.dighole.vaultcore.uniffi.clearSharedLogs
import net.dighole.vaultcore.uniffi.readSharedLogs
import net.dighole.vaultcore.uniffi.setLogFilePath
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong

/**
 * Shared vault.log operations use vault-core when available, with a local file
 * fallback when the native library cannot be loaded. The optional app-scoped
 * external event log remains readable with authorized ADB.
 */
object VaultFileLogger {
    private const val TAG = "VaultFileLogger"
    private const val MAX_LOG_SIZE = 1024 * 1024L
    private const val LOG_FILE_NAME = "vault.log"
    private const val PREV_LOG_FILE_NAME = "vault.prev.log"

    private val writerThread = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "vault-file-logger").apply { isDaemon = true }
    }

    @Volatile
    private var logFile: File? = null

    private var prevLogFile: File? = null

    @Volatile
    private var nativeLogging = false

    private var eventFile: File? = null
    private val eventSequence = AtomicLong()

    @Suppress("TooGenericExceptionCaught")
    @Synchronized
    fun init(context: android.content.Context) {
        if (logFile != null) return
        try {
            val logsDir = File(context.filesDir, "logs")
            logsDir.mkdirs()
            logFile = File(logsDir, LOG_FILE_NAME)
            prevLogFile = File(logsDir, PREV_LOG_FILE_NAME)
            logFile?.absolutePath?.let { path ->
                try {
                    setLogFilePath(path)
                    nativeLogging = true
                } catch (error: LinkageError) {
                    Log.w(TAG, "vault-bridge native library unavailable; using local logs", error)
                }
            }
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

    val currentLogPath: String?
        get() = logFile?.absolutePath

    /** Queue Kotlin records; file writes happen synchronously on this writer thread. */
    @Suppress("TooGenericExceptionCaught")
    fun log(priority: Int, tag: String, message: String, throwable: Throwable? = null) {
        val timestampMs = System.currentTimeMillis()
        val level = when (priority) {
            Log.VERBOSE -> "VERBOSE"
            Log.DEBUG -> "DEBUG"
            Log.INFO -> "INFO"
            Log.WARN -> "WARNING"
            Log.ERROR -> "ERROR"
            else -> "INFO"
        }
        val stackTrace = throwable?.let { Log.getStackTraceString(it) }
        writerThread.execute {
            try {
                val text = buildString {
                    append(message)
                    stackTrace?.let { append('\n').append(it) }
                }
                try {
                    if (nativeLogging) {
                        appendSharedLog(level, tag, text, timestampMs.toULong())
                    } else {
                        appendFallback(level, tag, text, timestampMs)
                    }
                } catch (_: LinkageError) {
                    nativeLogging = false
                    appendFallback(level, tag, text, timestampMs)
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to write log line", e)
            }
        }
    }

    /** Low-volume lifecycle events; app-scoped copy is readable with authorized ADB. */
    @Suppress("TooGenericExceptionCaught")
    fun event(tag: String, message: String) {
        val entry = "seq=${eventSequence.incrementAndGet()} elapsedMs=${SystemClock.elapsedRealtime()} " +
            "thread=${Thread.currentThread().name} [$tag] $message"
        log(Log.INFO, tag, entry)
        val file = eventFile ?: return
        writerThread.execute {
            try {
                rotateIfNeeded(file, File(file.parentFile, "vpn-events.prev.log"))
                file.appendText(entry + "\n")
            } catch (e: Exception) {
                Log.w(TAG, "Failed to write diagnostic event", e)
            }
        }
    }

    /** Queue UI reads/clears behind Kotlin writes; native writes remain append-safe. */
    suspend fun readLogs(): String = queuedLogs(false)
    suspend fun clearAndRead(): String = queuedLogs(true)

    @Suppress("TooGenericExceptionCaught")
    private suspend fun queuedLogs(clear: Boolean): String = kotlinx.coroutines.suspendCancellableCoroutine { continuation ->
        writerThread.execute {
            try {
                if (clear) {
                    try {
                        if (nativeLogging) clearSharedLogs() else clearFallback()
                    } catch (_: LinkageError) {
                        nativeLogging = false
                        clearFallback()
                    }
                    eventFile?.let { file ->
                        FileOutputStream(file, false).use { stream -> stream.flush() }
                        val backup = File(file.parentFile, "vpn-events.prev.log")
                        if (backup.exists() && !backup.delete()) {
                            throw java.io.IOException("Failed to clear event log backup")
                        }
                    }
                }
                val content = try {
                    if (nativeLogging) readSharedLogs() else readFallback()
                } catch (_: LinkageError) {
                    nativeLogging = false
                    readFallback()
                }
                if (continuation.isActive) continuation.resumeWith(Result.success(content))
            } catch (error: Exception) {
                if (continuation.isActive) continuation.resumeWith(Result.failure(error))
            }
        }
    }

    private fun appendFallback(level: String, tag: String, text: String, timestampMs: Long) {
        val file = logFile ?: return
        val previous = prevLogFile ?: return
        LocalVaultLog.append(file, previous, level, tag, text, timestampMs)
    }

    private fun readFallback(): String {
        val file = logFile ?: return ""
        val previous = prevLogFile ?: return ""
        return LocalVaultLog.read(file, previous)
    }

    private fun clearFallback() {
        val file = logFile ?: return
        val previous = prevLogFile ?: return
        LocalVaultLog.clear(file, previous)
    }

    private fun rotateIfNeeded(file: File, prev: File) {
        if (file.exists() && file.length() > MAX_LOG_SIZE) {
            prev.delete()
            if (!file.renameTo(prev)) {
                Log.w(TAG, "Log rotation failed")
            }
        }
    }
}

internal object LocalVaultLog {
    private const val MAX_LOG_SIZE = 1024 * 1024L
    private val timestampFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS'Z'", Locale.US).apply {
        timeZone = TimeZone.getTimeZone("UTC")
    }

    fun append(file: File, previous: File, level: String, tag: String, text: String, timestampMs: Long) {
        rotateIfNeeded(file, previous)
        val timestamp = timestampFormat.format(Date(timestampMs))
        val lines = text.split('\n').let { parts ->
            if (parts.lastOrNull()?.isEmpty() == true) parts.dropLast(1) else parts
        }
        val record = lines.joinToString("") { "[$timestamp] [$level] [$tag] $it\n" }
        FileOutputStream(file, true).use { it.write(record.toByteArray(Charsets.UTF_8)) }
    }

    fun read(file: File, previous: File): String = listOf(previous, file)
        .filter { it.exists() }
        .flatMap { it.readLines() }
        .filter { it.isNotEmpty() }
        .joinToString("\n")

    fun clear(file: File, previous: File) {
        for (path in listOf(file, previous)) {
            FileOutputStream(path, false).use { stream -> stream.flush() }
        }
    }

    private fun rotateIfNeeded(file: File, previous: File) {
        if (file.exists() && file.length() > MAX_LOG_SIZE) {
            previous.delete()
            if (!file.renameTo(previous)) {
                Log.w("VaultFileLogger", "Log rotation failed")
            }
        }
    }
}
