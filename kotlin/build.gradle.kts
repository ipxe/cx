import java.net.URL
import org.jetbrains.dokka.gradle.DokkaTask
import org.jetbrains.dokka.gradle.GradlePassConfigurationImpl

/* Dependencies */
val uuidDependency: String by project
val bouncyCastleDependency: String by project

/* Documentation URLs */
val bouncyCastleDocs: String by project

/* Miscellaneous other version numbers */
val androidSdkVersion: String by project
val dokkaJdkVersion: String by project

/* Gradle plugins */
plugins {
    kotlin("multiplatform")
    id("com.android.library")
    id("org.jlleitschuh.gradle.ktlint")
    id("org.jetbrains.dokka")
}

/* Non-plugin repositories */
repositories {
    mavenCentral()
    jcenter()
    google()
}

/* Android SDK configuration */
android {
    compileSdkVersion(androidSdkVersion.toInt())
    sourceSets {
        val main by getting {
            manifest.apply {
                srcFile("src/androidMain/AndroidManifest.xml")
            }
        }
    }
}

/* Main build configuration */
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
                api(uuidDependency)
            }
        }

        val jvmMain by getting {
            dependencies {
                implementation(bouncyCastleDependency)
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

/* Linting */
ktlint {
    verbose.set(true)
    outputToConsole.set(true)
}

/* Documentation
 *
 * The Dokka plugin's "global" block doesn't work for most options;
 * work around this by defining and reusing a lambda.
 */
val dokkaOptions: GradlePassConfigurationImpl.() -> Unit = {
    includeNonPublic = false
    jdkVersion = dokkaJdkVersion.toInt()
    externalDocumentationLink {
        url = URL(bouncyCastleDocs)
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
