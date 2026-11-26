// SPDX-License-Identifier: MIT
package net.dighole.vault.data

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.edit
import java.io.IOException
import java.nio.file.Files
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VaultConfigStoreTest {
    private class Fixture {
        val dir = Files.createTempDirectory("vault-config-test").toFile()
        private var scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        private fun open() = PreferenceDataStoreFactory.create(scope = scope) {
            dir.resolve("config.preferences_pb")
        }
        var disk = open()
        var failEncrypt = false
        var failDecrypt = false
        var failCommit = false
        var pauseCommit = false
        val reachedCommit = CompletableDeferred<Unit>()
        val releaseCommit = CompletableDeferred<Unit>()
        val store: VaultConfigStore
            get() = VaultConfigStore(
                dataStore = object : DataStore<Preferences> {
                    override val data: Flow<Preferences> get() = disk.data
                    override suspend fun updateData(
                        transform: suspend (Preferences) -> Preferences
                    ): Preferences = disk.updateData {
                        val updated = transform(it)
                        if (failCommit) throw IOException("injected disk failure")
                        if (pauseCommit) {
                            pauseCommit = false
                            reachedCommit.complete(Unit)
                            releaseCommit.await()
                        }
                        updated
                    }
                },
                encrypt = {
                    if (failEncrypt) throw IOException("Keystore unavailable")
                    "cipher:$it"
                },
                decrypt = {
                    if (failDecrypt) throw IOException("Keystore locked")
                    check(it.startsWith("cipher:"))
                    it.removePrefix("cipher:")
                },
                clearLegacyPassword = {}
            )

        suspend fun close() {
            scope.coroutineContext[Job]!!.cancelAndJoin()
            dir.deleteRecursively()
        }
    }

    private val first = VaultConfig(
        name = "First", host = "first.example", port = 1001, password = "first-password",
        dnsIpv4 = "1.1.1.1", dnsIpv6 = "2001:4860:4860::8888"
    )
    private val second = VaultConfig(
        name = "Second", host = "second.example", port = 1002, password = "second-password",
        dnsIpv4 = "8.8.8.8", dnsIpv6 = "2606:4700:4700::1001", mtu = "1380"
    )

    @Test
    fun profileCrud() = runBlocking {
        val f = Fixture()
        try {
            f.store.write(first)
            f.store.write(second)
            assertEquals("First", f.store.read().selectedProfileName)
            f.store.select("Second")
            assertEquals(second, f.store.read().selected)
            val renamed = first.copy(name = "Personal", host = "renamed.example")
            f.store.write(renamed, originalName = "First")
            val stored = f.store.read()
            assertEquals(listOf("Personal", "Second"), stored.profiles.map { it.name })
            assertEquals(renamed, stored.profiles.first())
            f.store.select("Personal")
            f.store.delete("Personal")
            assertEquals("Second", f.store.read().selectedProfileName)
            f.store.delete("Second")
            assertEquals(VaultProfiles(), f.store.read())
        } finally {
            f.close()
        }
    }

    @Test
    fun probeSettings() = runBlocking {
        val f = Fixture()
        try {
            f.store.writeProbeDomains("github.com,t.co")
            f.store.write(first)
            f.store.read()
            assertEquals("github.com,t.co", f.store.readProbeDomains())
            f.store.writeProbeDomains("")
            assertEquals("", f.store.readProbeDomains())
        } finally {
            f.close()
        }
    }

    @Test
    fun duplicateName() = runBlocking {
        val f = Fixture()
        try {
            f.store.write(first)
            val error = runCatching { f.store.write(first.copy(name = "FIRST")) }.exceptionOrNull()
            assertTrue(error is IllegalArgumentException)
            assertEquals(listOf("First"), f.store.read().profiles.map { it.name })
        } finally {
            f.close()
        }
    }

    @Test
    fun legacyIgnored() = runBlocking {
        val f = Fixture()
        try {
            f.disk.edit {
                it[ConfigKeys.HOST] = "legacy.example"
                it[ConfigKeys.PASSWORD] = "legacy"
                it[ConfigKeys.DNS] = "1.1.1.1"
            }
            assertEquals(VaultProfiles(), f.store.read())
            val prefs = f.disk.data.first()
            assertNull(prefs[ConfigKeys.HOST])
            assertNull(prefs[ConfigKeys.PASSWORD])
            assertNull(prefs[ConfigKeys.DNS])
        } finally {
            f.close()
        }
    }

    @Test(timeout = 15000)
    fun concurrentWrites() = runBlocking {
        val f = Fixture()
        try {
            f.store.write(first)
            f.pauseCommit = true
            val writer = async(Dispatchers.Default) {
                f.store.write(first.copy(host = "updated.example"), originalName = first.name)
            }
            f.reachedCommit.await()
            val reader = async(Dispatchers.Default) { f.store.read() }
            val otherWriter = async(Dispatchers.Default) { f.store.write(second) }
            f.releaseCommit.complete(Unit)
            writer.await()
            val observed = observedOrEmpty(reader)
            otherWriter.await()
            assertTrue(observed.host == "first.example" || observed.host == "updated.example")
            assertEquals(2, f.store.read().profiles.size)
        } finally {
            f.close()
        }
    }

    private suspend fun observedOrEmpty(reader: kotlinx.coroutines.Deferred<VaultProfiles>): VaultConfig =
        reader.await().profiles.firstOrNull { it.name == first.name } ?: VaultConfig()

    @Test
    fun commitFailure() = runBlocking {
        val f = Fixture()
        try {
            f.store.write(first)
            f.failCommit = true
            assertTrue(runCatching { f.store.write(first.copy(host = "new.example"), originalName = first.name) }.isFailure)
            f.failCommit = false
            assertEquals(first, f.store.read().selected)
        } finally {
            f.close()
        }
    }

    @Test(timeout = 15000)
    fun cancelledCommit() = runBlocking {
        val f = Fixture()
        try {
            f.store.write(first)
            f.pauseCommit = true
            val writer = async(Dispatchers.Default) {
                f.store.write(first.copy(host = "new.example"), originalName = first.name)
            }
            f.reachedCommit.await()
            writer.cancelAndJoin()
            f.releaseCommit.complete(Unit)
            assertEquals(first, f.store.read().selected)
        } finally {
            f.close()
        }
    }

    @Test
    fun plaintextRecovery() = runBlocking {
        val f = Fixture()
        try {
            f.failEncrypt = true
            f.store.write(first)
            assertEquals(first, f.store.read().selected)
            f.failEncrypt = false
            assertEquals(first, f.store.read().selected)
        } finally {
            f.close()
        }
    }

    @Test
    fun decryptFailure() = runBlocking {
        val f = Fixture()
        try {
            f.store.write(first)
            f.failDecrypt = true
            assertTrue(runCatching { f.store.read() }.isFailure)
            f.failDecrypt = false
            assertEquals(first, f.store.read().selected)
        } finally {
            f.close()
        }
    }
}
