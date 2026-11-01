package net.dighole.vault

import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Spinner
import android.widget.Toast
import androidx.fragment.app.Fragment

internal class LanguageSelector(private val fragment: Fragment, private val languageSpinner: Spinner) {
    private val languages = listOf(
        LocaleHelper.LANGUAGE_SYSTEM,
        LocaleHelper.LANGUAGE_ENGLISH,
        LocaleHelper.LANGUAGE_CHINESE,
        LocaleHelper.LANGUAGE_CHINESE_TW,
        LocaleHelper.LANGUAGE_JAPANESE,
        LocaleHelper.LANGUAGE_SPANISH
    )

    fun bind() {
        val displayNames = languages.map { LocaleHelper.getLanguageDisplayName(it) }
        val adapter =
            ArrayAdapter(fragment.requireContext(), R.layout.configure_language_item, displayNames)
        adapter.setDropDownViewResource(R.layout.configure_language_dropdown_item)
        languageSpinner.adapter = adapter

        val currentLanguage = LocaleHelper.getSavedLanguage(fragment.requireContext())
        val currentPosition = languages.indexOf(currentLanguage)
        languageSpinner.setSelection(currentPosition, false)

        languageSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(
                parent: AdapterView<*>?,
                view: View?,
                position: Int,
                id: Long
            ) {

                if (position != languages.indexOf(LocaleHelper.getSavedLanguage(fragment.requireContext()))) {
                    val selectedLanguage = languages[position]
                    changeLanguage(selectedLanguage)
                }
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
    }

    private fun changeLanguage(languageCode: String) {
        LocaleHelper.setLocale(fragment.requireContext(), languageCode)

        val displayName = LocaleHelper.getLanguageDisplayName(languageCode)
        Toast.makeText(
            fragment.requireContext(),
            fragment.getString(R.string.language_changed, displayName),
            Toast.LENGTH_SHORT
        ).show()

        fragment.activity?.recreate()
    }

}
