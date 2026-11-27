// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Rect
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.GestureDetector
import android.view.MotionEvent
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.fragment.app.Fragment
import com.google.android.material.bottomnavigation.BottomNavigationView
import com.google.android.material.textfield.TextInputLayout

class MainActivity : BaseActivity() {

    private lateinit var bottomNav: BottomNavigationView
    private var showingProfileEditor = false
    private val inputTaps by lazy {
        GestureDetector(this, object : GestureDetector.SimpleOnGestureListener() {
            override fun onDown(event: MotionEvent) = true

            override fun onSingleTapUp(event: MotionEvent): Boolean {
                val field = currentFocus as? EditText ?: return false
                val inputArea = generateSequence(field as View) { it.parent as? View }.firstOrNull {
                    it is TextInputLayout || it.id == R.id.probeDomainsField
                } ?: field
                val bounds = Rect()
                if (inputArea.getLocalVisibleRect(bounds)) {
                    val location = IntArray(2)
                    inputArea.getLocationOnScreen(location)
                    bounds.offset(location[0], location[1])
                }
                if (!bounds.contains(event.rawX.toInt(), event.rawY.toInt())) dismissInputKeyboard()
                return false
            }
        })
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        bottomNav = findViewById(R.id.bottomNav)

        bottomNav.isItemActiveIndicatorEnabled = true
        applyCompactNavigationLabels()
        val root = findViewById<View>(R.id.mainRoot)
        root.viewTreeObserver.addOnGlobalFocusChangeListener { previous, next ->
            if (previous is EditText && next !is EditText) hideInputKeyboard()
        }
        ViewCompat.setOnApplyWindowInsetsListener(root) { target, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
            target.setPadding(bars.left, bars.top, bars.right, maxOf(bars.bottom, ime.bottom))
            updateNavigationVisibility(insets)
            WindowInsetsCompat.CONSUMED
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
                val editor = supportFragmentManager.findFragmentByTag(TAG_CONFIGURE) as? ConfigureFragment
                if (bottomNav.selectedItemId == R.id.nav_configure && editor?.navigateBack() == true) return
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

    private fun applyCompactNavigationLabels() {
        val configuration = resources.configuration
        if (configuration.screenWidthDp > 360 && configuration.fontScale < 1.3f) return
        for ((id, shortTitle) in listOf(
            R.id.nav_status to R.string.nav_status_compact,
            R.id.nav_configure to R.string.nav_configure_compact,
            R.id.nav_diagnostics to R.string.nav_diagnostics_compact
        )) {
            val item = bottomNav.menu.findItem(id)
            item.contentDescription = item.title
            item.setTitle(shortTitle)
        }
    }

    fun setProfileEditorVisible(visible: Boolean) {
        showingProfileEditor = visible
        val root = findViewById<View>(R.id.mainRoot)
        updateNavigationVisibility(ViewCompat.getRootWindowInsets(root))
    }

    private fun updateNavigationVisibility(insets: WindowInsetsCompat?) {
        val hide = showingProfileEditor || insets?.isVisible(WindowInsetsCompat.Type.ime()) == true
        findViewById<View>(R.id.bottomNavFrame).visibility = if (hide) View.GONE else View.VISIBLE
    }

    fun openNewProfile() {
        navigateTo(R.id.nav_configure)
        supportFragmentManager.setFragmentResult(ConfigureFragment.NEW_PROFILE_REQUEST, Bundle())
    }

    override fun dispatchTouchEvent(event: MotionEvent): Boolean {
        val handled = super.dispatchTouchEvent(event)
        inputTaps.onTouchEvent(event)
        return handled
    }

    fun dismissInputKeyboard() {
        if (currentFocus !is EditText) return
        findViewById<View>(R.id.mainRoot).requestFocus()
        hideInputKeyboard()
    }

    fun dismissKeyboardOnDone(field: EditText) {
        field.setOnEditorActionListener { _, action, _ ->
            if (action != EditorInfo.IME_ACTION_DONE) return@setOnEditorActionListener false
            dismissInputKeyboard()
            true
        }
    }

    private fun hideInputKeyboard() {
        WindowCompat.getInsetsController(window, window.decorView).hide(WindowInsetsCompat.Type.ime())
    }

    private fun showFragment(tag: String, factory: () -> Fragment) {
        dismissInputKeyboard()
        if (tag != TAG_CONFIGURE) setProfileEditorVisible(false)
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
