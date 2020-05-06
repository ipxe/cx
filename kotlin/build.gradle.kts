plugins {
    kotlin("multiplatform")
    id("com.android.library")
}

repositories {
    mavenCentral()
    jcenter()
    google()
}

android {
    compileSdkVersion(29)
    sourceSets {
        val main by getting {
            manifest.apply {
                srcFile("src/androidMain/AndroidManifest.xml")
            }
        }
    }
}

kotlin {

    android()

    jvm()

    linuxX64("native") {
        val main by compilations.getting
        val libcx by main.cinterops.creating
        val openssl by main.cinterops.creating
    }

    sourceSets {

        val commonMain by getting {
            dependencies {
                api("com.benasher44:uuid:0.1.0")
            }
        }

        val jvmMain by getting {
            dependencies {
                implementation("org.bouncycastle:bcpkix-jdk15on:1.65")
            }
        }

        val jvmTest by getting {
            dependencies {
                implementation(kotlin("test-junit"))
            }
        }

        val androidMain by getting {
            dependsOn(jvmMain)
        }

        val androidTest by getting {
            dependsOn(jvmTest)
        }

        all {
            dependencies {
                implementation(kotlin("stdlib"))
            }
        }

    }

}
