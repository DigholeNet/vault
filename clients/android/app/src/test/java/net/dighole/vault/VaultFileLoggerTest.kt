package net.dighole.vault

import org.junit.Assert.assertEquals
import org.junit.Test
import java.nio.file.Files

class VaultFileLoggerTest {
    @Test fun fallbackLifecycle() {
        val directory = Files.createTempDirectory("vault-log-test").toFile()
        try {
            val current = directory.resolve("vault.log")
            val previous = directory.resolve("vault.prev.log")
            LocalVaultLog.append(current, previous, "INFO", "test", "first\nsecond", 1)
            assertEquals(
                "[1970-01-01 00:00:00.001Z] [INFO] [test] first\n" +
                    "[1970-01-01 00:00:00.001Z] [INFO] [test] second",
                current.readText().trim()
            )
            current.renameTo(previous)
            LocalVaultLog.append(current, previous, "INFO", "test", "third", 2)
            assertEquals(listOf("first", "second", "third"), LocalVaultLog.read(current, previous).lines().map {
                it.substringAfterLast(' ')
            })
            LocalVaultLog.clear(current, previous)
            assertEquals("", LocalVaultLog.read(current, previous))
        } finally {
            directory.deleteRecursively()
        }
    }

}
