import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
//    kotlin("multiplatform") version "2.1.0"
//    id("com.android.library") version "8.9.1"
//    id("org.jetbrains.kotlin.plugin.serialization") version "2.1.21" // Optional, if you need serialization
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidLibrary)
    alias(libs.plugins.composeMultiplatform)
    alias(libs.plugins.composeCompiler)
    alias(libs.plugins.serialization)
//    id("maven-publish")
}

group = "com.krzysobo"
version = "1.0.0"

kotlin {
    androidTarget {
        @OptIn(ExperimentalKotlinGradlePluginApi::class)
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_11)
        }
    }

//    androidTarget {
////        publishLibraryVariants("release")
//    }

    jvm("desktop")

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(compose.runtime)
                implementation(compose.foundation)
                implementation(compose.material)
                implementation(compose.ui)
                implementation(compose.components.resources)
                implementation(compose.components.uiToolingPreview)
                implementation(libs.androidx.lifecycle.viewmodel)
                implementation(libs.androidx.lifecycle.runtime.compose)
                implementation(compose.materialIconsExtended)  // icons for desktop/others
                implementation(libs.bouncyCastle)

//                implementation("org.bouncycastle:bcprov-jdk18on:1.81")
                // Add other common dependencies (e.g., kotlinx.serialization if needed)
            }
        }
        val androidMain by getting {
            dependencies {
                implementation(compose.preview)
                implementation(libs.androidx.activity.compose)
                implementation(libs.bouncyCastle)
                // Android-specific dependencies, if any
            }
        }
        val desktopMain by getting {
            dependencies {
                implementation(compose.desktop.currentOs)
                implementation(libs.kotlinx.coroutines.swing)
                implementation(compose.materialIconsExtended)  // icons for desktop/others
                implementation(libs.bouncyCastle)
                // Desktop-specific dependencies, if any
            }
        }
    }
}

android {
    compileSdk = 35
    namespace = "com.example.sobocryptolib"
    sourceSets["main"].manifest.srcFile("src/androidMain/AndroidManifest.xml")
    defaultConfig {
        minSdk = 24
        targetSdk = lint.targetSdk
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            /*
                --> fix for the following BouncyCastle's error:
                2 files found with path 'META-INF/versions/9/OSGI-INF/MANIFEST.MF' from inputs:
                 - org.bouncycastle:bcprov-jdk18on:1.81/bcprov-jdk18on-1.81.jar
                 - org.jspecify:jspecify:1.0.0/jspecify-1.0.0.jar
                Adding a packaging block may help, please refer to
             */
            excludes += "META-INF/versions/9/OSGI-INF/MANIFEST.MF"
        }

    }

//    publishing {
//        singleVariant("release") {
//            withSourcesJar()
//        }
//    }
    // =====

    // =====
}
