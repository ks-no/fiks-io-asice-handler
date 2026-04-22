# fiks-io-asice-handler
![GitHub](https://img.shields.io/github/license/ks-no/fiks-io-asice-handler)
[![Maven Central](https://img.shields.io/maven-central/v/no.ks.fiks/fiks-io-asice-handler.svg)](https://search.maven.org/search?q=g:no.ks.fiks%20a:fiks-io-asice-handler)
![GitHub last commit](https://img.shields.io/github/last-commit/ks-no/fiks-io-asice-handler.svg)
![GitHub Release Date](https://img.shields.io/github/release-date/ks-no/fiks-io-asice-handler.svg)

Java library for creating, encrypting, and decrypting [ASiC-E](https://www.etsi.org/deliver/etsi_ts/102900_102999/102918/01.03.01_60/ts_102918v010301p.pdf) (Associated Signature Containers, Extended) packages, as used by [FIKS IO](https://developers.fiks.ks.no/tjenester/fiksprotokoll/fiksio/). Wraps the [commons-asic](https://github.com/ks-no/asic) library with a streaming-friendly API supporting concurrent operations.

## Requirements

- Java 17 or later

## Installation

**Maven:**
```xml
<dependency>
    <groupId>no.ks.fiks</groupId>
    <artifactId>fiks-io-asice-handler</artifactId>
    <version><!-- see Maven Central badge above --></version>
</dependency>
```

**Gradle:**
```groovy
implementation 'no.ks.fiks:fiks-io-asice-handler:<version>'
```

## Usage

### Setup

`AsicHandler` implements `AutoCloseable` and should be closed when no longer needed.

```java
ExecutorService executor = Executors.newFixedThreadPool(2); // minimum 2 threads
PrivateKey privateKey = // java.security.PrivateKey used for decryption
KeyStore keyStore = // java.security.KeyStore containing the signing certificate

KeystoreHolder keyStoreHolder = KeystoreHolder.builder()
    .withKeyStore(keyStore)
    .withKeyStorePassword("keystorePassword")
    .withKeyAlias("keyAlias")
    .withKeyPassword("keyPassword")
    .build();

AsicHandler asicHandler = AsicHandler.builder()
    .withPrivatNokkel(privateKey)
    .withExecutorService(executor)
    .withKeyStoreHolder(keyStoreHolder)
    .build();
```

### Encrypt

```java
X509Certificate recipientCert = // certificate of the recipient
List<Content> payload = List.of(
    new StreamContent(new FileInputStream("document.pdf"), "document.pdf")
);

InputStream encryptedStream = asicHandler.encrypt(recipientCert, payload);
```

### Decrypt to ZipInputStream

```java
InputStream encryptedAsicData = // encrypted ASiC-E package

try (ZipInputStream zip = asicHandler.decrypt(encryptedAsicData)) {
    ZipEntry entry;
    while ((entry = zip.getNextEntry()) != null) {
        // process entry.getName() / zip stream
    }
}
```

### Decrypt to file

```java
InputStream encryptedAsicData = // encrypted ASiC-E package
Path targetPath = Path.of("/output/dir");

asicHandler.writeDecrypted(encryptedAsicData, targetPath);
```

## Building

```bash
mvn clean install
```

## Dependencies and maintenance

Dependency updates are managed by Dependabot (daily, Maven ecosystem).


