pluginManagement {

    val androidVersion = "3.6.0"
    val kotlinVersion = "1.3.72"

    repositories {
        gradlePluginPortal()
        mavenCentral()
        jcenter()
        google()
    }

    resolutionStrategy {
        eachPlugin {
            if (requested.id.id.startsWith("org.jetbrains.kotlin")) {
                useVersion(kotlinVersion)
            }
            if (requested.id.id.startsWith("com.android")) {
                useModule("com.android.tools.build:gradle:$androidVersion")
            }
        }
    }
}
