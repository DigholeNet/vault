import com.android.build.api.dsl.CommonExtension
import java.util.Properties

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.detekt) apply false
}

extra["androidTargets"] = linkedMapOf(
    "arm64-v8a" to "aarch64-linux-android",
    "armeabi-v7a" to "arm-linux-androideabi",
    "x86_64" to "x86_64-linux-android"
)

fun readNdkVersion(ndkHome: File): String? {
    val sourceProperties = ndkHome.resolve("source.properties")
    if (!sourceProperties.isFile) return null
    return Properties().apply {
        sourceProperties.inputStream().use { load(it) }
    }.getProperty("Pkg.Revision")
        ?.trim()
        ?.takeIf { it.isNotEmpty() }
}

fun compareNdkVersions(left: String, right: String): Int {
    val leftParts = left.split('.').map { it.substringBefore('-').toLongOrNull() ?: 0L }
    val rightParts = right.split('.').map { it.substringBefore('-').toLongOrNull() ?: 0L }
    for (index in 0 until maxOf(leftParts.size, rightParts.size)) {
        val result = leftParts.getOrElse(index) { 0L }
            .compareTo(rightParts.getOrElse(index) { 0L })
        if (result != 0) return result
    }
    return 0
}

// Use the same NDK for cargo-ndk and app symbol stripping:
// ANDROID_NDK_HOME first, then the highest installed version. If none exists,
// ndkVersion lets AGP download the pinned fallback.
val sdkDir = System.getenv("ANDROID_HOME")
    ?: System.getenv("ANDROID_SDK_ROOT")
    ?: Properties().apply {
        rootProject.file("local.properties").takeIf { it.exists() }?.inputStream()?.use { load(it) }
    }.getProperty("sdk.dir")
    ?: "${System.getProperty("user.home")}/Library/Android/sdk"

val environmentNdk = System.getenv("ANDROID_NDK_HOME")
    ?.takeIf { it.isNotBlank() }
    ?.let { homePath ->
        val home = File(homePath)
        val version = readNdkVersion(home)
            ?: throw GradleException(
                "ANDROID_NDK_HOME does not point to a valid NDK: $homePath"
            )
        version to home
    }

val installedNdkHomes =
    File(sdkDir, "ndk").listFiles()?.filter { it.isDirectory }.orEmpty() +
        listOf(File(sdkDir, "ndk-bundle")).filter { it.isDirectory }
val discoveredNdk = installedNdkHomes.mapNotNull { home ->
    readNdkVersion(home)?.let { version -> version to home }
}.maxWithOrNull { left, right ->
    compareNdkVersions(left.first, right.first)
}
val selectedNdk = environmentNdk ?: discoveredNdk
val selectedNdkVersion = selectedNdk?.first ?: "27.3.13750724"

subprojects {
    for (androidPlugin in listOf("com.android.application", "com.android.library")) {
        pluginManager.withPlugin(androidPlugin) {
            extensions.configure<CommonExtension>("android") {
                ndkVersion = selectedNdkVersion
                selectedNdk?.second?.let { ndkPath = it.absolutePath }
            }
        }
    }
}
