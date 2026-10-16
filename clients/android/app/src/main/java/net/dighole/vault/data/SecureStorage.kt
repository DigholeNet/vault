// SPDX-License-Identifier: MIT
package net.dighole.vault.data

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

private const val ANDROID_KEYSTORE = "AndroidKeyStore"
private const val KEY_ALIAS = "vault_secure_storage_key"
private const val PREFS_NAME = "vault_secure_store"
private const val KEY_PASSWORD = "secure_password"
private const val TRANSFORMATION = "AES/GCM/NoPadding"
private const val GCM_IV_LENGTH = 12
private const val GCM_TAG_LENGTH_BITS = 128

/**
 * Exception thrown when secure storage initialization or operation fails.
 * Typically caused by Android Keystore unavailability (e.g. device restore,
 * security update, or corrupted key material).
 */
class SecureStorageException(message: String, cause: Throwable? = null) :
    Exception(message, cause)

/**
 * Encrypted storage for sensitive configuration values.
 *
 * Encrypts values with an AES-256-GCM key held in the Android Keystore;
 * only the resulting ciphertext (IV-prefixed, Base64) touches disk in a
 * plain SharedPreferences file. All operations are synchronous; callers
 * that need suspend semantics should wrap in [withContext].
 */
class SecureStorage(context: Context) {

    private val prefs =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private fun getOrCreateSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.let {
            return it.secretKey
        }
        val keyGenerator =
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        keyGenerator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return keyGenerator.generateKey()
    }

    private fun encrypt(plainText: String): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        // Keystore GCM generates the IV itself (randomized encryption is
        // mandatory); read it back and persist it with the ciphertext.
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateSecretKey())
        val cipherText = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(cipher.iv + cipherText, Base64.NO_WRAP)
    }

    private fun decrypt(encoded: String): String {
        val bytes = Base64.decode(encoded, Base64.NO_WRAP)
        if (bytes.size <= GCM_IV_LENGTH) {
            throw SecureStorageException("Corrupted secure storage entry")
        }
        val iv = bytes.copyOfRange(0, GCM_IV_LENGTH)
        val cipherText = bytes.copyOfRange(GCM_IV_LENGTH, bytes.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateSecretKey(), GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
        return String(cipher.doFinal(cipherText), Charsets.UTF_8)
    }

    /**
     * Persists the VPN password encrypted with the device-specific Keystore key.
     */
    // Keystore/Security/IO failure modes vary by device; wrap them uniformly
    // so callers only need to handle SecureStorageException.
    @Suppress("TooGenericExceptionCaught")
    fun savePassword(password: String) {
        try {
            prefs.edit().putString(KEY_PASSWORD, encrypt(password)).apply()
        } catch (e: Exception) {
            throw SecureStorageException("Failed to encrypt and store password", e)
        }
    }

    /**
     * Reads the encrypted password, or null if not set.
     */
    @Suppress("TooGenericExceptionCaught")
    fun getPassword(): String? {
        val encoded = prefs.getString(KEY_PASSWORD, null) ?: return null
        return try {
            decrypt(encoded)
        } catch (e: SecureStorageException) {
            throw e
        } catch (e: Exception) {
            throw SecureStorageException("Failed to decrypt stored password", e)
        }
    }

    /**
     * Removes the stored password.
     */
    fun clearPassword() {
        prefs.edit().remove(KEY_PASSWORD).apply()
    }
}
