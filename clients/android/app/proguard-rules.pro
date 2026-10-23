# ProGuard rules for Vault

# Keep UniFFI generated bindings and public wrapper classes (called from Rust/JNA)
-keep class net.dighole.vaultcore.uniffi.** { *; }
-keepclassmembers class net.dighole.vaultcore.uniffi.** { *; }
-keep class net.dighole.vaultcore.Edge { *; }
-keep class net.dighole.vaultcore.EdgeConfig { *; }
-keep class net.dighole.vaultcore.EdgeException { *; }
-keep class net.dighole.vaultcore.PeerId { *; }

# Keep JNA classes used by UniFFI
-keep class com.sun.jna.** { *; }
-dontwarn com.sun.jna.**

# Keep coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-keep class kotlinx.coroutines.android.** { *; }
-keep class kotlinx.coroutines.flow.** { *; }
-dontwarn kotlinx.coroutines.**

# Keep VPN Service
-keep class net.dighole.vault.VaultVpnService { *; }

# Keep DataStore & preferences
-keep class androidx.datastore.** { *; }
-keepclassmembers class androidx.datastore.** { *; }
-dontwarn androidx.datastore.**

# Keep app configuration classes (used by DataStore / preferences)
-keep class net.dighole.vault.data.VaultConfig { *; }

# Keep AndroidX core, appcompat, material components
-keep class androidx.core.app.** { *; }
-keep class androidx.appcompat.** { *; }
-keep class com.google.android.material.** { *; }
-dontwarn androidx.core.**
-dontwarn androidx.appcompat.**
-dontwarn com.google.android.material.**

# Keep notification-related classes
-keep class androidx.core.app.NotificationCompat { *; }
-keep class androidx.core.app.NotificationManagerCompat { *; }

# Keep PendingIntent and related intent classes
-keep class android.app.PendingIntent { *; }
-keep class android.content.Intent { *; }

# Debug/verbose log calls (e.g. server IPs in VaultVpnService) must not ship in
# release builds; warnings and errors stay.
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
}
