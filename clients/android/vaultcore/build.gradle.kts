plugins {
    id("com.android.library")
    alias(libs.plugins.detekt)
}

// NDKs need not provide native libraries for every Android API. For example,
// an API-36 app can use an NDK whose newest sysroot libraries target API 35.
// Use the closest available API at or below minSdk, common to all our ABIs.
fun resolveNdkPlatform(ndkHome: File, minSdk: Int, triples: Collection<String>): Int {
    val prebuilt = ndkHome.resolve("toolchains/llvm/prebuilt")
        .listFiles().orEmpty().singleOrNull { it.resolve("sysroot").isDirectory }
        ?: throw GradleException("Expected one NDK host sysroot under $ndkHome/toolchains/llvm/prebuilt")
    val libraries = prebuilt.resolve("sysroot/usr/lib")
    val platforms = triples.map { triple ->
        libraries.resolve(triple).listFiles().orEmpty()
            .filter { it.isDirectory }
            .mapNotNull { it.name.toIntOrNull() }
            .filter { it <= minSdk }
            .toSet()
    }
    val platform = platforms.reduce { common, available -> common intersect available }.maxOrNull()
        ?: throw GradleException("NDK $ndkHome has no common native API <= $minSdk for $triples")
    for (triple in triples) {
        for (name in listOf("crtbegin_so.o", "crtend_so.o", "libandroid.so", "liblog.so")) {
            val library = libraries.resolve("$triple/$platform/$name")
            if (!library.isFile) throw GradleException("Incomplete NDK sysroot: missing $library")
        }
    }
    return platform
}

@Suppress("UNCHECKED_CAST")
val androidTargets = rootProject.extra["androidTargets"] as Map<String, String>

android {
    namespace = "net.dighole.vaultcore"
    compileSdk = libs.versions.compile.sdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.min.sdk.get().toInt()

        ndk {
            abiFilters += androidTargets.keys
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

// Match the Apple script: explicit CARGO, custom CARGO_HOME/bin, PATH, then
// the default rustup location. Use an executable path for CARGO overrides.
val cargoName = if (System.getProperty("os.name").lowercase().contains("win")) "cargo.exe" else "cargo"
val cargoHomeBin = File(
    System.getenv("CARGO_HOME")?.takeIf { it.isNotBlank() }
        ?: "${System.getProperty("user.home")}/.cargo",
    "bin"
)
val cargoFromHome = System.getenv("CARGO_HOME")?.takeIf { it.isNotBlank() }
    ?.let { cargoHomeBin.resolve(cargoName).takeIf(File::canExecute) }
val cargoFromPath = System.getenv("PATH").orEmpty().split(File.pathSeparator)
    .asSequence().filter { it.isNotBlank() }
    .map { File(it, cargoName) }.firstOrNull { it.isFile && it.canExecute() }
val defaultCargo = File("${System.getProperty("user.home")}/.cargo/bin", cargoName)
val cargoExecutable = System.getenv("CARGO")?.takeIf { it.isNotBlank() }
    ?: (cargoFromHome ?: cargoFromPath ?: defaultCargo).absolutePath
val pathWithCargo = listOfNotNull(
    File(cargoExecutable).parent,
    cargoHomeBin.absolutePath,
    System.getenv("PATH")
).distinct().joinToString(File.pathSeparator)

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
    commandLine(cargoExecutable, "build")
}

tasks.register<Exec>("generateUniFFIBindings") {
    group = "rust"
    description = "Generates Kotlin UniFFI bindings from the Rust library."
    dependsOn("cargoBuildHost")
    workingDir = rustDir
    environment("PATH", pathWithCargo)
    environment("CARGO_TARGET_DIR", rustDir.resolve("target").absolutePath)
    commandLine(
        cargoExecutable, "run",
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
    // Keep frame pointers so native callstack sampling (Perfetto) can unwind.
    environment("RUSTFLAGS", "-Cforce-frame-pointers=yes")
    environment("PATH", pathWithCargo)
    environment("CARGO_TARGET_DIR", rustDir.resolve("target").absolutePath)
    doFirst {
        // Resolve lazily so AGP can provision the fallback NDK if necessary.
        val ndkHome = androidComponents.sdkComponents.ndkDirectory.get().asFile
        val minSdk = libs.versions.min.sdk.get().toInt()
        val nativePlatform = resolveNdkPlatform(ndkHome, minSdk, androidTargets.values)
        logger.lifecycle("cargo-ndk: NDK ${ndkHome.absolutePath}, native API $nativePlatform (app minSdk $minSdk)")
        environment("ANDROID_NDK_HOME", ndkHome.absolutePath)
        commandLine(
            listOf(cargoExecutable, "ndk", "--platform", nativePlatform.toString()) +
                androidTargets.keys.flatMap { listOf("-t", it) } +
                listOf("-o", "../android/vaultcore/src/main/jniLibs", "build", "--release")
        )
    }
}

tasks.register("testNdkPlatformSelection") {
    group = "verification"
    description = "Checks native API selection against representative NDK sysroot layouts."
    doLast {
        val fixtureRoot = temporaryDir.resolve("run-${System.nanoTime()}")
        fun fixture(name: String, apis: List<Int>): File {
            val home = fixtureRoot.resolve(name)
            for (triple in androidTargets.values) {
                for (api in apis) {
                    val directory = home.resolve("toolchains/llvm/prebuilt/test-host/sysroot/usr/lib/$triple/$api")
                    directory.mkdirs()
                    for (library in listOf("crtbegin_so.o", "crtend_so.o", "libandroid.so", "liblog.so")) {
                        directory.resolve(library).writeText("")
                    }
                }
            }
            return home
        }
        val older = fixture("older", listOf(21, 24, 35))
        check(resolveNdkPlatform(older, 36, androidTargets.values) == 35)
        check(resolveNdkPlatform(older, 25, androidTargets.values) == 24)
        check(resolveNdkPlatform(fixture("newer", listOf(35, 36, 37)), 36, androidTargets.values) == 36)
        val mixed = fixture("mixed", listOf(35, 36))
        check(
            mixed.resolve("toolchains/llvm/prebuilt/test-host/sysroot/usr/lib/arm-linux-androideabi/36")
                .renameTo(mixed.resolve("arm-api-36"))
        )
        check(resolveNdkPlatform(mixed, 36, androidTargets.values) == 35)
        check(runCatching { resolveNdkPlatform(older, 20, androidTargets.values) }.exceptionOrNull() is GradleException)
        val incomplete = fixture("incomplete", listOf(35))
        check(
            incomplete.resolve("toolchains/llvm/prebuilt/test-host/sysroot/usr/lib/aarch64-linux-android/35/liblog.so")
                .delete()
        )
        check(runCatching { resolveNdkPlatform(incomplete, 36, androidTargets.values) }.exceptionOrNull() is GradleException)
        check(runCatching { resolveNdkPlatform(fixtureRoot.resolve("missing"), 36, androidTargets.values) }.exceptionOrNull() is GradleException)
        fixtureRoot.deleteRecursively()
        logger.lifecycle("NDK native API selection checks passed")
    }
}

tasks.named("preBuild").configure {
    dependsOn("generateUniFFIBindings", "cargoNdkBuild")
}
