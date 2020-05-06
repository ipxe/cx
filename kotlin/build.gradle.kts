import java.net.URL
import org.jetbrains.dokka.gradle.DokkaTask
import org.jetbrains.dokka.gradle.GradlePassConfigurationImpl

plugins {
    kotlin("multiplatform")
    id("com.android.library")
    id("org.jlleitschuh.gradle.ktlint") version("9.2.1")
    id("org.jetbrains.dokka") version("0.10.1")
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

ktlint {
    verbose.set(true)
    outputToConsole.set(true)
}

/* The Dokka plugin's "global" block doesn't work for most options */
val dokkaOptions: GradlePassConfigurationImpl.() -> Unit = {
    includeNonPublic = false
    jdkVersion = 7
    externalDocumentationLink {
        url = URL("https://www.bouncycastle.org/docs/docs1.5on/index.html")
    }
}

tasks {
    val dokka by getting(DokkaTask::class) {
        multiplatform {
            val android by creating(dokkaOptions)
            val jvm by creating(dokkaOptions)
            val native by creating(dokkaOptions)
        }
    }
}
