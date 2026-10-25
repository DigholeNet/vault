// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.content.Context
import android.content.res.Configuration
import android.os.LocaleList
import androidx.core.app.LocaleManagerCompat
import net.dighole.vault.VaultVpnService.Companion.PREFS_NAME
import java.util.Locale

object LocaleHelper {
    private const val LANGUAGE_KEY = "app_language"

    const val LANGUAGE_SYSTEM = "system"
    const val LANGUAGE_ENGLISH = "en"
    const val LANGUAGE_CHINESE = "zh"
    const val LANGUAGE_CHINESE_TW = "zh_TW"
    const val LANGUAGE_JAPANESE = "ja"
    const val LANGUAGE_SPANISH = "es"

    /**
     * Set application locale to specific language.
     * Use LANGUAGE_SYSTEM to follow system default.
     */
    fun setLocale(context: Context, languageCode: String): Context {
        saveLanguage(context, languageCode)
        return updateResources(context, languageCode)
    }

    /**
     * Get saved language setting, defaults to system language.
     */
    fun getSavedLanguage(context: Context): String {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString(LANGUAGE_KEY, LANGUAGE_SYSTEM) ?: LANGUAGE_SYSTEM
    }

    private fun saveLanguage(context: Context, languageCode: String) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(LANGUAGE_KEY, languageCode)
            .apply()
    }

    private fun updateResources(context: Context, languageCode: String): Context {
        val locale = when (languageCode) {
            LANGUAGE_SYSTEM -> getSystemLocale(context)
            LANGUAGE_CHINESE_TW -> Locale.of("zh", "TW")
            else -> Locale.of(languageCode)
        }

        // Do NOT call Locale.setDefault(locale) — it mutates global JVM state,
        // is not thread-safe, and can interfere with third-party libraries.
        // Locale is applied per-Context via createConfigurationContext().

        val config = Configuration(context.resources.configuration)
        config.setLocales(LocaleList(locale))
        return context.createConfigurationContext(config)
    }

    /**
     * Get system locale, falling back to English if not supported.
     */
    private fun getSystemLocale(context: Context): Locale {
        val systemLocale = LocaleManagerCompat.getSystemLocales(context).get(0)

        return when (systemLocale?.language) {
            "zh" -> {
                when (systemLocale.country) {
                    "TW", "HK", "MO" -> Locale.of(LANGUAGE_CHINESE, "TW")
                    else -> Locale.of(LANGUAGE_CHINESE)
                }
            }

            "ja" -> Locale.of(LANGUAGE_JAPANESE)
            "es" -> Locale.of(LANGUAGE_SPANISH)
            else -> Locale.of(LANGUAGE_ENGLISH)
        }
    }

    /**
     * Apply saved locale or system default.
     * Called from BaseActivity.attachBaseContext before inflating localized views.
     */
    fun applySavedLocale(context: Context): Context {
        val language = getSavedLanguage(context)
        return updateResources(context, language)
    }

    fun getLanguageDisplayName(languageCode: String): String {
        return when (languageCode) {
            LANGUAGE_SYSTEM -> "System"
            LANGUAGE_ENGLISH -> "English"
            LANGUAGE_CHINESE -> "中文 (简体)"
            LANGUAGE_CHINESE_TW -> "中文 (繁體)"
            LANGUAGE_JAPANESE -> "日本語"
            LANGUAGE_SPANISH -> "Español"
            else -> languageCode
        }
    }

}
