// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import android.widget.Toast
import androidx.core.net.toUri
import androidx.fragment.app.Fragment
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import java.io.IOException

class AboutFragment : Fragment() {

    private lateinit var tvVersion: TextView
    private lateinit var tvWebsite: TextView

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

        view.findViewById<View>(R.id.action_licenses).setOnClickListener {
            try {
                val text = listOf("LICENSE", "NOTICE").joinToString("\n\n") { name ->
                    requireContext().assets.open(name).bufferedReader().use { it.readText() }
                }
                MaterialAlertDialogBuilder(requireContext()).setTitle(R.string.open_source_licenses)
                    .setMessage(text).setPositiveButton(android.R.string.ok, null).show()
            } catch (error: IOException) {
                Log.e("AboutFragment", "Could not load license notices", error)
                Toast.makeText(requireContext(), R.string.license_unavailable, Toast.LENGTH_SHORT).show()
            }
        }

        try {
            val packageInfo = requireContext().packageManager.getPackageInfo(
                requireContext().packageName,
                android.content.pm.PackageManager.PackageInfoFlags.of(0)
            )
            val versionName = packageInfo.versionName
            tvVersion.text = getString(R.string.version_format, versionName, BuildConfig.GIT_BUILD_ID)
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

    }

    companion object {
        fun newInstance() = AboutFragment()
    }
}
