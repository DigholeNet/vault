import java.util.Base64
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.detekt)
}

// Same build identity as Apple: commit count, with a timestamp for tracked local changes.
val gitBuildId = providers.exec {
    workingDir(rootProject.file("../.."))
    commandLine("bash", "-c", """
        commits=${'$'}(git rev-list --count HEAD 2>/dev/null || echo 0)
        if git diff-index --quiet HEAD -- 2>/dev/null; then
            echo "${'$'}commits"
        else
            echo "${'$'}commits.${'$'}(date +%Y%m%d%H%M)"
        fi
    """.trimIndent())
}.standardOutput.asText.get().trim()

android {
    namespace = "net.dighole.vault"
    compileSdk = libs.versions.compile.sdk.get().toInt()

    defaultConfig {
        applicationId = "net.dighole.vault"
        minSdk = libs.versions.min.sdk.get().toInt()
        targetSdk = libs.versions.target.sdk.get().toInt()
        versionCode = providers.gradleProperty("versionCode").map(String::toInt).orElse(1).get()
        versionName = providers.gradleProperty("versionName").orElse("1.0.0").get()
        buildConfigField("String", "GIT_BUILD_ID", "\"$gitBuildId\"")
    }

    signingConfigs {
        create("release") {
            val localProps = try {
                val props = Properties()
                rootProject.file("local.properties").takeIf { it.exists() }?.inputStream()?.use {
                    props.load(it)
                }
                props
            } catch (e: Exception) {
                null
            }

            val keystoreBase64 = localProps?.getProperty("signing.keyStoreBase64")
                ?: System.getenv("ANDROID_SIGNING_KEY_STORE_BASE64")
            val storePasswordValue = localProps?.getProperty("signing.keyStorePassword")
                ?: System.getenv("ANDROID_SIGNING_KEY_STORE_PASSWORD")
            val keyAliasValue = localProps?.getProperty("signing.keyAlias")
                ?: System.getenv("ANDROID_SIGNING_KEY_ALIAS")

            // The keystore travels as base64 text (same variable as CI), so
            // no real keystore file ever needs to live in the repository
            // tree; it is decoded into the build directory when configured.
            // Debug APKs use the Android debug signing key.
            val keystoreFile =
                layout.buildDirectory.file("signing/vault-release.keystore").get().asFile
            if (!keystoreBase64.isNullOrEmpty()) {
                keystoreFile.parentFile?.mkdirs()
                // Mime decoder: tolerates line-wrapped base64 output.
                keystoreFile.writeBytes(Base64.getMimeDecoder().decode(keystoreBase64))
            }
            storeFile = keystoreFile
            storePassword = storePasswordValue.orEmpty()
            keyAlias = keyAliasValue.orEmpty()
            // PKCS12 keystores (the default format) do not support a key
            // password different from the store password; use it for both.
            keyPassword = storePasswordValue.orEmpty()

            // Defer validation so debug builds do not fail when release signing
            // is not configured. Only enforce when a release task is actually executed.
            project.afterEvaluate {
                val isReleaseBuild = gradle.startParameter.taskNames.any {
                    it.contains("Release", ignoreCase = true)
                }
                if (isReleaseBuild) {
                    if (keystoreBase64.isNullOrEmpty()) {
                        throw GradleException(
                            "Release signing keystore not configured. " +
                                "Set signing.keyStoreBase64 in local.properties or ANDROID_SIGNING_KEY_STORE_BASE64 env var."
                        )
                    }
                    if (storePasswordValue.isNullOrEmpty()) {
                        throw GradleException(
                            "Release signing store password not configured. " +
                                "Set signing.keyStorePassword in local.properties or ANDROID_SIGNING_KEY_STORE_PASSWORD env var."
                        )
                    }
                    if (keyAliasValue.isNullOrEmpty()) {
                        throw GradleException(
                            "Release signing key alias not configured. " +
                                "Set signing.keyAlias in local.properties or ANDROID_SIGNING_KEY_ALIAS env var."
                        )
                    }
                }
            }

            enableV1Signing = true
            enableV2Signing = true
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfig = signingConfigs.getByName("release")
        }
        debug {
            isDebuggable = true
            applicationIdSuffix = ".debug"
        }
    }

    detekt {
        config.setFrom(files("$rootDir/detekt.yml"))
        buildUponDefaultConfig.set(false)
    }

    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_24
        targetCompatibility = JavaVersion.VERSION_24
    }

    // Auto-provision the compile JDK (foojay resolver in settings.gradle.kts),
    // so any JDK 17+ is enough to run Gradle itself.
    java {
        toolchain {
            languageVersion = JavaLanguageVersion.of(24)
        }
    }

    packaging {
        jniLibs {
            // JNA AAR ships native libs for many ABIs; only keep the ones we target.
            excludes += setOf(
                "lib/armeabi/libjnidispatch.so",
                "lib/mips/libjnidispatch.so",
                "lib/mips64/libjnidispatch.so",
                "lib/x86/libjnidispatch.so"
            )
        }
    }
}

dependencies {
    implementation(project(":vaultcore"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.material)
    implementation(libs.kotlinx.coroutines.android)

    implementation(libs.datastore.preferences)

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.test.junit)
}
