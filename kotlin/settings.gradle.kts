pluginManagement {

    val kotlinVersion = "1.3.72"

    repositories {
	gradlePluginPortal()
	mavenCentral()
    }

    resolutionStrategy {
	eachPlugin {
	    if (requested.id.id.startsWith("org.jetbrains.kotlin")) {
		useVersion(kotlinVersion)
	    }
	}
    }

}
