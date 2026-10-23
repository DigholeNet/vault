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
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.bottomnavigation.BottomNavigationView

class MainActivity : BaseActivity() {

    private lateinit var bottomNav: BottomNavigationView
    private lateinit var topAppBar: MaterialToolbar

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        topAppBar = findViewById(R.id.topAppBar)
        bottomNav = findViewById(R.id.bottomNav)

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

                R.id.nav_about -> {
                    showFragment(TAG_ABOUT) { AboutFragment.newInstance() }
                    true
                }

                else -> false
            }
        }

        if (savedInstanceState == null) {
            bottomNav.selectedItemId = R.id.nav_status
        }
    }

    /**
     * Navigate to the specified bottom navigation item.
     * Called by Fragments to switch tabs without directly manipulating Activity views.
     */
    fun navigateTo(itemId: Int) {
        bottomNav.selectedItemId = itemId
    }

    private fun showFragment(tag: String, factory: () -> Fragment) {
        val transaction = supportFragmentManager.beginTransaction()

        supportFragmentManager.findFragmentByTag(TAG_STATUS)?.let { transaction.hide(it) }
        supportFragmentManager.findFragmentByTag(TAG_CONFIGURE)?.let { transaction.hide(it) }
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

    companion object {
        private const val TAG = "MainActivity"
        private const val TAG_STATUS = "status"
        private const val TAG_CONFIGURE = "configure"
        private const val TAG_ABOUT = "about"
        private const val REQUEST_NOTIFICATION_PERMISSION = 1001
    }
}
