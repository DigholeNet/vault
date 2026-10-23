import java.util.Properties

plugins {
    id("com.android.library")
    alias(libs.plugins.detekt)
}

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

// Use one NDK for AGP and cargo-ndk: ANDROID_NDK_HOME first, then the
// highest installed version. If none exists, ndkVersion lets AGP download
// the pinned fallback.
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
val vaultcoreNdkVersion = selectedNdk?.first ?: "27.3.13750724"
val androidNdkHome = selectedNdk?.second?.absolutePath
    ?: File(sdkDir, "ndk/$vaultcoreNdkVersion").absolutePath

android {
    namespace = "net.dighole.vaultcore"
    compileSdk = libs.versions.compile.sdk.get().toInt()
    if (selectedNdk == null) {
        ndkVersion = vaultcoreNdkVersion
    } else {
        ndkPath = androidNdkHome
    }

    defaultConfig {
        minSdk = libs.versions.min.sdk.get().toInt()

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_24
        targetCompatibility = JavaVersion.VERSION_24
    }

    // Auto-provision the compile JDK (foojay resolver in settings.gradle.kts).
    java {
        toolchain {
            languageVersion = JavaLanguageVersion.of(24)
        }
    }

    sourceSets {
        getByName("main") {
            jniLibs.directories.add("src/main/jniLibs")
        }
    }
}

dependencies {
    implementation(libs.kotlinx.coroutines.core)
    // Use the AAR artifact so that JNA's native libs (libjnidispatch.so)
    // are packaged for Android.
    implementation(libs.jna) {
        artifact {
            type = "aar"
        }
    }

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
}

detekt {
    config.setFrom(files("$rootDir/detekt.yml"))
    source.setFrom(files("src/main/java/net/dighole/vaultcore"))
    buildUponDefaultConfig.set(false)
}

tasks.withType<dev.detekt.gradle.Detekt>().configureEach {
    exclude("**/uniffi/**")
}

// Ensure Gradle can find cargo / cargo-ndk even when the daemon was started
// without ~/.cargo/bin on PATH (common when building from an IDE).
val cargoBin = "${System.getProperty("user.home")}/.cargo/bin"
val pathWithCargo = cargoBin + File.pathSeparator + (System.getenv("PATH") ?: "")

// Host cdylib filename is OS-dependent: macOS .dylib, Linux .so, Windows .dll.
val hostLibName = run {
    val os = System.getProperty("os.name").lowercase()
    when {
        os.contains("mac") -> "libvault_bridge.dylib"
        os.contains("win") -> "vault_bridge.dll"
        else -> "libvault_bridge.so"
    }
}

// The shared UniFFI bridge crate lives at <repo>/clients/bridge; its
// target dir is pinned next to the crate.
val rustDir = file("../../bridge")

tasks.register<Exec>("cargoBuildHost") {
    group = "rust"
    description = "Builds vault-bridge host library for UniFFI bindgen."
    workingDir = rustDir
    environment("PATH", pathWithCargo)
    environment("CARGO_TARGET_DIR", rustDir.resolve("target").absolutePath)
    commandLine("$cargoBin/cargo", "build")
}

tasks.register<Exec>("generateUniFFIBindings") {
    group = "rust"
    description = "Generates Kotlin UniFFI bindings from the Rust library."
    dependsOn("cargoBuildHost")
    workingDir = rustDir
    environment("PATH", pathWithCargo)
    environment("CARGO_TARGET_DIR", rustDir.resolve("target").absolutePath)
    commandLine(
        "$cargoBin/cargo", "run",
        "--features", "bindgen",
        "--bin", "uniffi-bindgen",
        "--",
        "generate",
        "--library", "target/debug/$hostLibName",
        "--language", "kotlin",
        "--out-dir", "../android/vaultcore/src/main/java"
    )
}

tasks.register<Exec>("cargoNdkBuild") {
    group = "rust"
    description = "Builds Rust vault-bridge crate for Android targets using cargo-ndk."
    workingDir = rustDir
    environment(
        "ANDROID_NDK_HOME",
        androidNdkHome
    )
    // Keep frame pointers so native callstack sampling (Perfetto) can unwind.
    environment("RUSTFLAGS", "-Cforce-frame-pointers=yes")
    environment("PATH", pathWithCargo)
    environment("CARGO_TARGET_DIR", rustDir.resolve("target").absolutePath)
    commandLine(
        "$cargoBin/cargo", "ndk",
        "-t", "arm64-v8a",
        "-t", "armeabi-v7a",
        "-t", "x86_64",
        "-o", "../android/vaultcore/src/main/jniLibs",
        "build", "--release"
    )
}

tasks.named("preBuild").configure {
    dependsOn("generateUniFFIBindings", "cargoNdkBuild")
}
