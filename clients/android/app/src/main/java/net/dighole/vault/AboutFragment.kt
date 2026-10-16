// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import androidx.core.net.toUri
import androidx.fragment.app.Fragment

class AboutFragment : Fragment() {

    private lateinit var tvVersion: TextView
    private lateinit var tvWebsite: TextView
    private lateinit var languageSpinner: Spinner

    private val languages = listOf(
        LocaleHelper.LANGUAGE_SYSTEM,
        LocaleHelper.LANGUAGE_ENGLISH,
        LocaleHelper.LANGUAGE_CHINESE,
        LocaleHelper.LANGUAGE_CHINESE_TW,
        LocaleHelper.LANGUAGE_JAPANESE,
        LocaleHelper.LANGUAGE_SPANISH
    )

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.fragment_about, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        tvVersion = view.findViewById(R.id.tvVersion)
        tvWebsite = view.findViewById(R.id.tvWebsite)
        languageSpinner = view.findViewById(R.id.languageSpinner)

        try {
            val packageInfo = requireContext().packageManager.getPackageInfo(
                requireContext().packageName,
                android.content.pm.PackageManager.PackageInfoFlags.of(0)
            )
            val versionName = packageInfo.versionName
            val versionCode = packageInfo.longVersionCode
            tvVersion.text = getString(R.string.version_format, versionName, versionCode.toString())
        } catch (_e: Exception) {
            Log.e("AboutFragment", "Failed to get version", _e)
            tvVersion.text = getString(R.string.version_unknown)
        }

        tvWebsite.setOnClickListener {
            try {
                val intent = Intent(
                    Intent.ACTION_VIEW,
                    "https://github.com/DigholeNet/vault".toUri()
                )
                startActivity(intent)
            } catch (_e: Exception) {
                Log.e("AboutFragment", "Failed to open browser", _e)
                Toast.makeText(requireContext(), R.string.no_browser, Toast.LENGTH_SHORT).show()
            }
        }

        setupLanguageSpinner()
    }

    private fun setupLanguageSpinner() {
        val displayNames = languages.map { LocaleHelper.getLanguageDisplayName(it) }
        val adapter =
            ArrayAdapter(requireContext(), android.R.layout.simple_spinner_item, displayNames)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        languageSpinner.adapter = adapter

        val currentLanguage = LocaleHelper.getSavedLanguage(requireContext())
        val currentPosition = languages.indexOf(currentLanguage)
        languageSpinner.setSelection(currentPosition, false)

        languageSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(
                parent: AdapterView<*>?,
                view: View?,
                position: Int,
                id: Long
            ) {

                if (position != languages.indexOf(LocaleHelper.getSavedLanguage(requireContext()))) {
                    val selectedLanguage = languages[position]
                    changeLanguage(selectedLanguage)
                }
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
    }

    private fun changeLanguage(languageCode: String) {
        LocaleHelper.setLocale(requireContext(), languageCode)

        val displayName = LocaleHelper.getLanguageDisplayName(languageCode)
        Toast.makeText(
            requireContext(),
            getString(R.string.language_changed, displayName),
            Toast.LENGTH_SHORT
        ).show()

        activity?.recreate()
    }

    companion object {
        fun newInstance() = AboutFragment()
    }
}
