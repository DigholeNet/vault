// SPDX-License-Identifier: MIT
package net.dighole.vault.data

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.edit
import java.io.IOException
import java.nio.file.Files
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
        private var scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        private fun open() = PreferenceDataStoreFactory.create(scope = scope) {
            dir.resolve("config.preferences_pb")
        }
        var disk = open()
        var legacy: String? = null
        var failEncrypt = false
        var failDecrypt = false
        var failLegacyRead = false
        var failCommit = false
        var keepLegacy = false
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
                readLegacyPassword = {
                    if (failLegacyRead) throw IOException("legacy Keystore locked")
                    legacy
                },
                clearLegacyPassword = { if (!keepLegacy) legacy = null }
            )
        suspend fun reopen() {
            scope.coroutineContext[Job]!!.cancelAndJoin()
            scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
            disk = open()
        }
        suspend fun close() {
            scope.coroutineContext[Job]!!.cancelAndJoin()
            dir.deleteRecursively()
        }
    }
    private val first = VaultConfig(host = "first.example", port = 1001, password = "first-password",
        dnsIpv4 = "1.1.1.1", dnsIpv6 = "2001:4860:4860::8888")
    private val second = VaultConfig(host = "second.example", port = 1002, password = "second-password",
        dnsIpv4 = "8.8.8.8", dnsIpv6 = "2606:4700:4700::1111", mtu = "1380", probeDomains = "github.com,t.co")

    @Test fun dnsMigration() = runBlocking {
        val f = Fixture()
        try {
            f.disk.edit { it[ConfigKeys.DNS] = "1.1.1.1, 2001:4860:4860::8888,8.8.8.8,2606:4700:4700::1111" }
            val config = f.store.read()
            assertEquals("1.1.1.1,8.8.8.8", config.dnsIpv4)
            assertEquals("2001:4860:4860::8888,2606:4700:4700::1111", config.dnsIpv6)
            assertNull(f.disk.data.first()[ConfigKeys.DNS])
            f.reopen()
            assertEquals(config, f.store.read())
        } finally { f.close() }
    }

    @Test fun dnsMigrationKeepsOverrides() = runBlocking {
        val f = Fixture()
        try {
            f.disk.edit {
                it[ConfigKeys.DNS] = "1.1.1.1,2001:4860:4860::8888"
                it[ConfigKeys.DNS_IPV4] = ""
                it[ConfigKeys.DNS_IPV6] = "2606:4700:4700::1111"
            }
            val config = f.store.read()
            assertEquals("", config.dnsIpv4)
            assertEquals("2606:4700:4700::1111", config.dnsIpv6)
            assertNull(f.disk.data.first()[ConfigKeys.DNS])
        } finally { f.close() }
    }

    @Test fun dnsMigrationCommitFailure() = runBlocking {
        val f = Fixture()
        try {
            f.disk.edit { it[ConfigKeys.DNS] = "1.1.1.1,2001:4860:4860::8888" }
            f.failCommit = true
            try {
                f.store.read()
                throw AssertionError("migration unexpectedly succeeded")
            } catch (_: IOException) { }
            val prefs = f.disk.data.first()
            assertEquals("1.1.1.1,2001:4860:4860::8888", prefs[ConfigKeys.DNS])
            assertNull(prefs[ConfigKeys.DNS_IPV4])
            assertNull(prefs[ConfigKeys.DNS_IPV6])
            f.failCommit = false
            assertEquals("2001:4860:4860::8888", f.store.read().dnsIpv6)
        } finally { f.close() }
    }

    @Test(timeout = 15000)
    fun concurrentAccessKeepsWholeConfigs() = runBlocking {
        val f = Fixture()
        try {
            f.store.write(first)
            f.pauseCommit = true
            val writer = async(Dispatchers.Default) { f.store.write(second) }
            f.reachedCommit.await()
            val reader = async(Dispatchers.Default) { f.store.read() }
            val otherWriter = async(Dispatchers.Default) { f.store.write(first) }
            f.releaseCommit.complete(Unit)
            writer.await()
            val observed = reader.await()
            otherWriter.await()
            assertTrue(observed == first || observed == second)
            assertEquals(first, f.store.read())
            f.reopen()
            assertEquals(first, f.store.read())
        } finally { f.close() }
    }

    @Test
    fun failedCommitPreservesPreviousConfig() = runBlocking {
        val f = Fixture()
        try {
            f.store.write(first)
            f.failCommit = true
            try {
                f.store.write(second)
                throw AssertionError("write unexpectedly succeeded")
            } catch (_: IOException) { }
            f.failCommit = false
            assertEquals(first, f.store.read())
            f.reopen()
            assertEquals(first, f.store.read())
        } finally { f.close() }
    }

    @Test(timeout = 15000)
    fun cancelledCommit() = runBlocking {
        val f = Fixture()
        try {
            f.store.write(first)
            f.pauseCommit = true
            val writer = async(Dispatchers.Default) { f.store.write(second) }
            f.reachedCommit.await()
            writer.cancelAndJoin()
            f.releaseCommit.complete(Unit)
            assertEquals(first, f.store.read())
            f.reopen()
            assertEquals(first, f.store.read())
        } finally { f.close() }
    }

    @Test
    fun encryptedMigration() = runBlocking {
        val f = Fixture()
        try {
            f.legacy = "new encrypted password"
            f.disk.edit {
                it[ConfigKeys.HOST] = "legacy.example"
                it[ConfigKeys.PASSWORD] = "stale plaintext"
            }
            val config = f.store.read()
            assertEquals("legacy.example", config.host)
            assertEquals("new encrypted password", config.password)
            val prefs = f.disk.data.first()
            assertNull(prefs[ConfigKeys.PASSWORD])
            assertEquals("cipher:new encrypted password", prefs[ConfigKeys.ENCRYPTED_PASSWORD])
            assertNull(f.legacy)
        } finally { f.close() }
    }

    @Test
    fun keystoreRecoveryMigration() = runBlocking {
        val f = Fixture()
        try {
            f.legacy = "stale credential"
            f.keepLegacy = true
            f.failEncrypt = true
            f.store.write(second)
            assertEquals(second, f.store.read())
            assertEquals(second.password, f.disk.data.first()[ConfigKeys.PASSWORD])
            f.failEncrypt = false
            assertEquals(second, f.store.read())
            assertNull(f.disk.data.first()[ConfigKeys.PASSWORD])
            f.reopen()
            assertEquals(second, f.store.read())
        } finally { f.close() }
    }

    @Test
    fun failedMigrationCommit() = runBlocking {
        val f = Fixture()
        try {
            f.legacy = "recovery"
            f.disk.edit { it[ConfigKeys.HOST] = "legacy.example" }
            f.failCommit = true
            try {
                f.store.read()
                throw AssertionError("migration unexpectedly succeeded")
            } catch (_: IOException) { }
            assertEquals("recovery", f.legacy)
            assertNull(f.disk.data.first()[ConfigKeys.ENCRYPTED_PASSWORD])
            f.failCommit = false
            assertEquals("recovery", f.store.read().password)
            assertNull(f.legacy)
        } finally { f.close() }
    }

    @Test
    fun unreadableCiphertextIsPreserved() = runBlocking {
        val f = Fixture()
        try {
            f.store.write(first)
            f.legacy = "stale credential"
            f.failDecrypt = true
            try {
                f.store.read()
                throw AssertionError("read unexpectedly succeeded")
            } catch (_: IOException) { }
            assertEquals("cipher:first-password", f.disk.data.first()[ConfigKeys.ENCRYPTED_PASSWORD])
            assertEquals("stale credential", f.legacy)
            f.failDecrypt = false
            assertEquals(first, f.store.read())
        } finally { f.close() }
    }

    @Test
    fun unreadableLegacyCredential() = runBlocking {
        val f = Fixture()
        try {
            f.legacy = "recovery"
            f.failLegacyRead = true
            try {
                f.store.read()
                throw AssertionError("read unexpectedly succeeded")
            } catch (_: IOException) { }
            assertEquals("recovery", f.legacy)
            assertNull(f.disk.data.first()[ConfigKeys.ENCRYPTED_PASSWORD])
            f.failLegacyRead = false
            assertEquals("recovery", f.store.read().password)
        } finally { f.close() }
    }

    @Test
    fun plaintextRecovery() = runBlocking {
        val f = Fixture()
        try {
            f.disk.edit { it[ConfigKeys.PASSWORD] = "recovery" }
            f.failEncrypt = true
            assertEquals("recovery", f.store.read().password)
            assertEquals("recovery", f.disk.data.first()[ConfigKeys.PASSWORD])
            f.failEncrypt = false
            assertEquals("recovery", f.store.read().password)
            assertNull(f.disk.data.first()[ConfigKeys.PASSWORD])
        } finally { f.close() }
    }
}
