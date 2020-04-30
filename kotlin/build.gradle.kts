plugins {
    kotlin("multiplatform")
}

repositories {
    mavenCentral()
}

kotlin {

    jvm()

    linuxX64("native") {
	val main by compilations.getting
	val interop by main.cinterops.creating
    }

    sourceSets {

	val commonMain by getting {
	    dependencies {
		api("com.benasher44:uuid:0.1.0")
	    }
	}

	val jvmMain by getting {
	    dependencies {
		implementation(kotlin("stdlib"))
	    }
	}

	val jvmTest by getting {
	    dependencies {
		implementation(kotlin("test-junit"))
	    }
	}

    }

}
