/* Plugin configuration */
pluginManagement {

    /* Plugin versions */
    val androidPlugin: String by settings
    val dokkaPlugin: String by settings
    val kotlinPlugin: String by settings
    val ktlintPlugin: String by settings

    /* Plugin-only repositories */
    repositories {
        gradlePluginPortal()
        mavenCentral()
        jcenter()
        google()
    }

    /* Work around the inability of Gradle to expose property values
     * within the plugins block, and the failure of the Android Gradle
     * Plugin to use the standard naming scheme.
     */
    resolutionStrategy {
        eachPlugin {
            when (requested.id.id) {
                "com.android.library" ->
                    useModule("com.android.tools.build:gradle:$androidPlugin")
                "org.jetbrains.dokka" ->
                    useVersion(dokkaPlugin)
                "org.jetbrains.kotlin.multiplatform" ->
                    useVersion(kotlinPlugin)
                "org.jlleitschuh.gradle.ktlint" ->
                    useVersion(ktlintPlugin)
            }
        }
    }
}
