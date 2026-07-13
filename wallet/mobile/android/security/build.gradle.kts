plugins {
    id("com.android.library") version "8.5.2"
    kotlin("android") version "2.0.20"
}

android {
    namespace = "org.noosphere.wallet.security"
    compileSdk = 35

    defaultConfig {
        minSdk = 31
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation("androidx.annotation:annotation:1.9.1")
}
