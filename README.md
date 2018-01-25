[![Donation](https://img.shields.io/badge/donate-please-brightgreen.svg)](https://www.paypal.me/janrabe) [![About Jan Rabe](https://img.shields.io/badge/about-me-green.svg)](https://about.me/janrabe)
# Android-PGP [![](https://jitpack.io/v/kibotu/Android-PGP.svg)](https://jitpack.io/#kibotu/Android-PGP) [![Javadoc](https://img.shields.io/badge/javadoc-SNAPSHOT-green.svg)](https://jitpack.io/com/github/kibotu/Android-PGP/master-SNAPSHOT/javadoc/index.html) [![Build Status](https://travis-ci.org/kibotu/Android-PGP.svg?branch=master)](https://travis-ci.org/kibotu/Android-PGP) [![API](https://img.shields.io/badge/API-15%2B-brightgreen.svg?style=flat)](https://android-arsenal.com/api?level=15)  [![Gradle Version](https://img.shields.io/badge/gradle-4.4.1-green.svg)](https://docs.gradle.org/current/release-notes) [![Retrolambda](https://img.shields.io/badge/kotlin-1.2.20-green.svg)](https://kotlinlang.org/) [![Licence](https://img.shields.io/badge/licence-Apache%202-blue.svg)](https://raw.githubusercontent.com/kibotu/Android-PGP/master/LICENSE)

## Introduction

Adds PGP encryption and decryption support.

![Screenshot](https://raw.githubusercontent.com/kibotu/Android-PGP/master/screenshot.png)


## How to use

1.1 [Generate a Key-Pair](https://github.com/kibotu/Android-PGP/blob/master/app/src/main/java/net/kibotu/pgp/app/MainActivity.kt#L19-L21)

    val krgen = Pgp.generateKeyRingGenerator("password".toCharArray())
    val publicKey = Pgp.genPGPPublicKey(krgen)
    val privateKey = Pgp.genPGPPrivKey(krgen)

1.2 or [provide one pair](https://github.com/kibotu/Android-PGP/blob/master/app/src/main/java/net/kibotu/pgp/app/MainActivity.kt#L47-L48)

    Pgp.setPublicKey("rsa.pub".openFromAssets())
    Pgp.setPrivateKey("rsa".openFromAssets())

2 [Encrypt](https://github.com/kibotu/Android-PGP/blob/master/app/src/main/java/net/kibotu/pgp/app/MainActivity.kt#L50)

    encrypted = Pgp.encrypt("my secret message")

3 [Decrypt](https://github.com/kibotu/Android-PGP/blob/master/app/src/main/java/net/kibotu/pgp/app/MainActivity.kt#L51)

    decrypted = Pgp.decrypt(encrypted, "password")

## How to install

    implementation 'com.github.kibotu:android-pgp:-SNAPSHOT'

## How to build

    graldew clean build

### CI

    gradlew clean assembleRelease test javadoc

#### Build Requirements

- JDK8
- Android Build Tools 27.0.2
- Android SDK 27

## Contributors

- [Jan Rabe](jan.rabe@kibotu.net)
- [joey_g216](https://stackoverflow.com/users/546489/joey-g216)

### License

This library also includes the [The Bouncy Castle Crypto package](https://github.com/rtyley/spongycastle) which is licensed under [MIT](https://github.com/rtyley/spongycastle/blob/spongy-master/README.md).

<pre>
Copyright 2018 Jan Rabe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
</pre>
