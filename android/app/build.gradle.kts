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
        versionCode = 6
        versionName = "3.0"

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
    packaging {
        jniLibs {
            // ExecuTorch and fbjni may both carry the C++ runtime: one copy is enough.
            pickFirsts += "**/libc++_shared.so"
        }
    }
}

dependencies {
    implementation(libs.androidx.activity.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.androidx.core.ktx)
    implementation(libs.material)
    implementation("androidx.work:work-runtime-ktx:2.12.0")
    // Llama on the phone (update 44): ExecuTorch's runtime and LLM runner, the release the Pi's model
    // was exported with (1.5.1). It brings fbjni and SoLoader's native loader with it.
    implementation("org.pytorch:executorch-android:1.5.1")
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
}