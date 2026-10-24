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

    }

    companion object {
        fun newInstance() = AboutFragment()
    }
}
