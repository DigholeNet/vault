import java.util.Properties

plugins {
    id("com.android.library")
    alias(libs.plugins.detekt)
}

// NDK version used for both AGP and cargo-ndk. Pinned for reproducible
// builds; override with -PvaultNdkVersion=<version> or a vaultNdkVersion
// entry in ~/.gradle/gradle.properties to use an NDK you already have.
val vaultcoreNdkVersion =
    providers.gradleProperty("vaultNdkVersion").orElse("27.3.13750724").get()

android {
    namespace = "net.dighole.vaultcore"
    compileSdk = libs.versions.compile.sdk.get().toInt()
    ndkVersion = vaultcoreNdkVersion

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

// Resolve the NDK location portably: env first, then the SDK dir from
// ANDROID_HOME / local.properties, so CI and other machines work without
// machine-specific hardcoded paths.
val sdkDir = System.getenv("ANDROID_HOME")
    ?: System.getenv("ANDROID_SDK_ROOT")
    ?: Properties().apply {
        rootProject.file("local.properties").takeIf { it.exists() }?.inputStream()?.use { load(it) }
    }.getProperty("sdk.dir")
    ?: "${System.getProperty("user.home")}/Library/Android/sdk"
val androidNdkHome = System.getenv("ANDROID_NDK_HOME") ?: "$sdkDir/ndk/$vaultcoreNdkVersion"

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
