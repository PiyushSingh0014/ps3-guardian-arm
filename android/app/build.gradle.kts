plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.ps3guardian.app"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "com.ps3guardian.app"
        minSdk = 26
        targetSdk = 36
        versionCode = 3
        versionName = "2.1"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            optimization {
                enable = true
                packageScope = setOf("androidx.**", "kotlin.**", "kotlinx.**")
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

dependencies {
    implementation(libs.androidx.activity.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.androidx.core.ktx)
    implementation(libs.material)
    implementation("androidx.work:work-runtime-ktx:2.12.0")
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
}