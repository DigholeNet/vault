// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.google.android.material.bottomnavigation.BottomNavigationView

class MainActivity : BaseActivity() {

    private lateinit var bottomNav: BottomNavigationView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        bottomNav = findViewById(R.id.bottomNav)

        bottomNav.isItemActiveIndicatorEnabled = true
        val root = findViewById<android.view.View>(R.id.mainRoot)
        androidx.core.view.ViewCompat.setOnApplyWindowInsetsListener(root) { target, insets ->
            val bars = insets.getInsets(androidx.core.view.WindowInsetsCompat.Type.systemBars())
            val ime = insets.getInsets(androidx.core.view.WindowInsetsCompat.Type.ime())
            target.setPadding(bars.left, bars.top, bars.right, maxOf(bars.bottom, ime.bottom))
            bottomNav.visibility = if (insets.isVisible(androidx.core.view.WindowInsetsCompat.Type.ime()))
                android.view.View.GONE else android.view.View.VISIBLE
            androidx.core.view.WindowInsetsCompat.CONSUMED
        }
        requestNotificationPermissionIfNeeded()

        bottomNav.setOnItemSelectedListener { item ->
            when (item.itemId) {
                R.id.nav_status -> {
                    showFragment(TAG_STATUS) { StatusFragment.newInstance() }
                    true
                }

                R.id.nav_configure -> {
                    showFragment(TAG_CONFIGURE) { ConfigureFragment.newInstance() }
                    true
                }

                R.id.nav_diagnostics -> {
                    showFragment(TAG_DIAGNOSTICS) { DiagnosticsFragment() }
                    true
                }
                R.id.nav_about -> {
                    showFragment(TAG_ABOUT) { AboutFragment.newInstance() }
                    true
                }

                else -> false
            }
        }

        bottomNav.selectedItemId = savedInstanceState?.getInt("selected_tab") ?: R.id.nav_status
        onBackPressedDispatcher.addCallback(this, object : androidx.activity.OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (bottomNav.selectedItemId != R.id.nav_status) navigateTo(R.id.nav_status)
                else { isEnabled = false; onBackPressedDispatcher.onBackPressed() }
            }
        })
    }

    /**
     * Navigate to the specified bottom navigation item.
     * Called by Fragments to switch tabs without directly manipulating Activity views.
     */
    fun navigateTo(itemId: Int) {
        bottomNav.selectedItemId = itemId
    }

    private fun showFragment(tag: String, factory: () -> Fragment) {
        findViewById<android.view.View>(R.id.mainRoot).setBackgroundColor(ContextCompat.getColor(this,
            if (tag == TAG_STATUS) R.color.status_background else R.color.vault_background))
        val transaction = supportFragmentManager.beginTransaction()

        supportFragmentManager.findFragmentByTag(TAG_STATUS)?.let { transaction.hide(it) }
        supportFragmentManager.findFragmentByTag(TAG_CONFIGURE)?.let { transaction.hide(it) }
        supportFragmentManager.findFragmentByTag(TAG_DIAGNOSTICS)?.let { transaction.hide(it) }
        supportFragmentManager.findFragmentByTag(TAG_ABOUT)?.let { transaction.hide(it) }

        val existing = supportFragmentManager.findFragmentByTag(tag)
        if (existing != null) {
            transaction.show(existing)
        } else {
            transaction.add(R.id.container, factory(), tag)
        }
        transaction.commit()
    }

    /**
     * Request POST_NOTIFICATIONS runtime permission on Android 13+ (API 33).
     * The permission is already declared in AndroidManifest.xml.
     */
    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return

        val granted = ContextCompat.checkSelfPermission(
            this,
            Manifest.permission.POST_NOTIFICATIONS
        ) == PackageManager.PERMISSION_GRANTED

        if (!granted) {
            ActivityCompat.requestPermissions(
                this,
                arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                REQUEST_NOTIFICATION_PERMISSION
            )
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        when (requestCode) {
            REQUEST_NOTIFICATION_PERMISSION -> {
                if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                    Log.d(TAG, "POST_NOTIFICATIONS permission granted")
                } else {
                    Log.w(TAG, "POST_NOTIFICATIONS permission denied")
                }
            }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putInt("selected_tab", bottomNav.selectedItemId)
        super.onSaveInstanceState(outState)
    }

    companion object {
        private const val TAG = "MainActivity"
        private const val TAG_STATUS = "status"
        private const val TAG_CONFIGURE = "configure"
        private const val TAG_DIAGNOSTICS = "diagnostics"
        private const val TAG_ABOUT = "about"
        private const val REQUEST_NOTIFICATION_PERMISSION = 1001
    }
}
