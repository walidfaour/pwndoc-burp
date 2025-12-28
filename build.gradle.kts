plugins {
    id("java")
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

group = "com.walidfaour.pwndoc"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.11")
    implementation("com.google.code.gson:gson:2.10.1")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

tasks.withType<JavaCompile>().configureEach {
    sourceCompatibility = "21"
    targetCompatibility = "21"
    options.encoding = "UTF-8"
}

tasks.jar {
    manifest {
        attributes(
            "Implementation-Title" to "PwnDoc BurpSuite Extension",
            "Implementation-Version" to version,
            "Implementation-Vendor" to "Walid Faour"
        )
    }
}

tasks.shadowJar {
    archiveClassifier.set("")
    mergeServiceFiles()
    dependencies {
        exclude(dependency("net.portswigger.burp.extensions:montoya-api"))
    }
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
