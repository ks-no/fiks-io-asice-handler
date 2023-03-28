package no.ks.fiks.io.asice;

import com.google.common.primitives.Bytes;
import lombok.extern.slf4j.Slf4j;
import no.ks.fiks.io.asice.model.KeystoreHolder;
import no.ks.fiks.io.asice.model.StreamContent;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.NullInputStream;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.*;

@Slf4j
class AsicHandlerTest {

    @Test
    @DisplayName("Krypter AsicPakke In Parallel With ThreadPool")
    void testKrypterAsicPakkeInParallelWithThreadPool() throws Exception {

        final ExecutorService executor = Executors.newFixedThreadPool(3);
        final ExecutorService executorInput = Executors.newFixedThreadPool(30);

        try {
            final AsicHandler asicHandler = AsicHandler.builder()
                .withPrivatNokkel(getPrivateKeyResource("/bob.key"))
                .withKeyStoreHolder(getKeystoreHolder())
                .withExecutorService(executor)
                .build();
            for(int i = 0; i< 25; i++) {
                executorInput.submit(() -> {
                    byte[] plaintext = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
                    InputStream encrypt = asicHandler.encrypt(
                        getPublicCertResource("bob.cert"),
                        singletonList(new StreamContent(new ByteArrayInputStream(plaintext), "payload.bin")));
                    log.info("started reading");
                    byte[] encrypted = new byte[0];
                    try {
                        encrypted = IOUtils.toByteArray(encrypt);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                    log.info("done reading");
                    try {
                        encrypt.close();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }

                    //den krypterte filen skal nidvendigvis være lengre enn plaintext
                    assertTrue(encrypted.length > plaintext.length);

                    //verifiser at plaintext payloaden ikke finnes i den krypterte filen
                    assertEquals(-1, Bytes.indexOf(encrypted, plaintext));
                });

            }
            executorInput.shutdown();
            assertTrue(executorInput.awaitTermination(120, TimeUnit.SECONDS));
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    @DisplayName("Krypter AsicPakke In Parallel With ForkJoinPool")
    void testKrypterAsicPakkeInParallelWithForkJoinPool() throws Exception {

        final ExecutorService executor = new ForkJoinPool(2);
        final ExecutorService executorInput = Executors.newFixedThreadPool(30);

        try {
            final AsicHandler asicHandler = AsicHandler.builder()
                .withPrivatNokkel(getPrivateKeyResource("/bob.key"))
                .withKeyStoreHolder(getKeystoreHolder())
                .withExecutorService(executor)
                .build();
            for(int i = 0; i< 25; i++) {
                executorInput.submit(() -> {
                    byte[] plaintext = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
                    InputStream encrypt = asicHandler.encrypt(
                        getPublicCertResource("bob.cert"),
                        singletonList(new StreamContent(new ByteArrayInputStream(plaintext), "payload.bin")));
                    log.info("started reading");
                    byte[] encrypted = new byte[0];
                    try {
                        encrypted = IOUtils.toByteArray(encrypt);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                    log.info("done reading");
                    try {
                        encrypt.close();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }

                    //den krypterte filen skal nidvendigvis være lengre enn plaintext
                    assertTrue(encrypted.length > plaintext.length);

                    //verifiser at plaintext payloaden ikke finnes i den krypterte filen
                    assertEquals(-1, Bytes.indexOf(encrypted, plaintext));
                });

            }
            executorInput.shutdown();
            assertTrue(executorInput.awaitTermination(120, TimeUnit.SECONDS));
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    @DisplayName("Verifiser at payload blir kryptert")
    void testKrypterStream() throws Exception {

        final ExecutorService executor = Executors.newFixedThreadPool(2);

        try {
            final AsicHandler asicHandler = AsicHandler.builder()
                .withPrivatNokkel(getPrivateKeyResource("/bob.key"))
                .withKeyStoreHolder(getKeystoreHolder())
                .withExecutorService(executor)
                .build();

            byte[] plaintext = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
            InputStream encrypt = asicHandler.encrypt(
                getPublicCertResource("bob.cert"),
                singletonList(new StreamContent(new ByteArrayInputStream(plaintext), "payload.bin")));
            log.info("started reading");
            byte[] encrypted = IOUtils.toByteArray(encrypt);
            log.info("done reading");
            encrypt.close();

            //den krypterte filen skal nidvendigvis være lengre enn plaintext
            assertTrue(encrypted.length > plaintext.length);

            //verifiser at plaintext payloaden ikke finnes i den krypterte filen
            assertEquals(-1, Bytes.indexOf(encrypted, plaintext));
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    @DisplayName("Verifiser at payload blir kryptert også uten privat nikkel")
    void testKrypterStreamUtenPrivatNokkel() throws Exception {

        final ExecutorService executor = Executors.newFixedThreadPool(2);

        try {
            final AsicHandler asicHandler = AsicHandler.builder()
                .withKeyStoreHolder(getKeystoreHolder())
                .withExecutorService(executor)
                .build();

            byte[] plaintext = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
            InputStream encrypt = asicHandler.encrypt(
                getPublicCertResource("bob.cert"),
                singletonList(new StreamContent(new ByteArrayInputStream(plaintext), "payload.bin")));
            log.info("started reading");
            byte[] encrypted = IOUtils.toByteArray(encrypt);
            log.info("done reading");
            encrypt.close();

            //den krypterte filen skal nidvendigvis være lengre enn plaintext
            assertTrue(encrypted.length > plaintext.length);

            //verifiser at plaintext payloaden ikke finnes i den krypterte filen
            assertEquals(-1, Bytes.indexOf(encrypted, plaintext));
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    @DisplayName("Test at vi kan dekryptere en payload til en zip stream")
    void testDekrypterStream() throws Exception {

        final ExecutorService executor = Executors.newFixedThreadPool(2);

        final AsicHandler asicHandler = AsicHandler.builder()
            .withPrivatNokkel(getPrivateKeyResource("/bob.key"))
            .withKeyStoreHolder(getKeystoreHolder())
            .withExecutorService(executor)
            .build();

        byte[] payload = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
        InputStream encrypted = asicHandler.encrypt(getPublicCertResource("bob.cert"), singletonList(new StreamContent(new ByteArrayInputStream(payload), "payload.txt")));
        ZipInputStream decrypt = asicHandler.decrypt(new ByteArrayInputStream(IOUtils.toByteArray(encrypted)));
        assertArrayEquals(payload, readBytes(decrypt).get("payload.txt"));
        decrypt.close();
        encrypted.close();
        executor.shutdownNow();
    }

    @Test
    @DisplayName("Test at en eller flere feile private keys kaster kryptering-feil og returnerer null")
    void testDekrypterStreamFeilPrivateKey() throws Exception {

        final ExecutorService executor = Executors.newFixedThreadPool(2);

        final AsicHandler asicHandler = AsicHandler.builder()
            .withPrivatNokkel(getPrivateKeyResource("/alice.key"))
            .withKeyStoreHolder(getKeystoreHolder())
            .withExecutorService(executor)
            .build();

        List<PrivateKey> privateKeys = new ArrayList<>();
        privateKeys.add(getPrivateKeyResource("/alice.key"));
        privateKeys.add(getPrivateKeyResource("/alice.key"));
        privateKeys.add(getPrivateKeyResource("/alice.key"));
        privateKeys.add(getPrivateKeyResource("/alice.key"));

        final AsicHandler asicHandlerList = AsicHandler.builder()
            .withPrivateNokkeler(privateKeys)
            .withKeyStoreHolder(getKeystoreHolder())
            .withExecutorService(executor)
            .build();

        byte[] payload = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
        InputStream encrypted = asicHandler.encrypt(getPublicCertResource("bob.cert"), singletonList(new StreamContent(new ByteArrayInputStream(payload), "payload.txt")));
        ZipInputStream decrypt = asicHandler.decrypt(new ByteArrayInputStream(IOUtils.toByteArray(encrypted)));
        ZipInputStream decryptWithList = asicHandlerList.decrypt(new ByteArrayInputStream(IOUtils.toByteArray(encrypted)));

        assertArrayEquals(null, readBytes(decrypt).get("payload.txt"));
        assertArrayEquals(null, readBytes(decryptWithList).get("payload.txt"));
        decrypt.close();
        decryptWithList.close();
        encrypted.close();
        executor.shutdownNow();
    }

    @Test
    @DisplayName("Test at en feil og en riktig private key blir riktig")
    void testDekrypterStreamToPrivateKey() throws Exception {

        final ExecutorService executor = Executors.newFixedThreadPool(2);

        List<PrivateKey> privateKeysAliceFirst = new ArrayList<>();
        List<PrivateKey> privateKeysBobFirst = new ArrayList<>();
        List<PrivateKey> privateKeysBobIMidtenAvMangeAlice = new ArrayList<>();
        privateKeysAliceFirst.add(getPrivateKeyResource("/alice.key"));
        privateKeysAliceFirst.add(getPrivateKeyResource("/bob.key"));

        privateKeysBobFirst.add(getPrivateKeyResource("/bob.key"));
        privateKeysBobFirst.add(getPrivateKeyResource("/alice.key"));

        privateKeysBobIMidtenAvMangeAlice.add(getPrivateKeyResource("/alice.key"));
        privateKeysBobIMidtenAvMangeAlice.add(getPrivateKeyResource("/alice.key"));
        privateKeysBobIMidtenAvMangeAlice.add(getPrivateKeyResource("/alice.key"));
        privateKeysBobIMidtenAvMangeAlice.add(getPrivateKeyResource("/alice.key"));
        privateKeysBobIMidtenAvMangeAlice.add(getPrivateKeyResource("/alice.key"));
        privateKeysBobIMidtenAvMangeAlice.add(getPrivateKeyResource("/alice.key"));
        privateKeysBobIMidtenAvMangeAlice.add(getPrivateKeyResource("/alice.key"));
        privateKeysBobIMidtenAvMangeAlice.add(getPrivateKeyResource("/alice.key"));
        privateKeysBobIMidtenAvMangeAlice.add(getPrivateKeyResource("/alice.key"));
        privateKeysBobIMidtenAvMangeAlice.add(getPrivateKeyResource("/bob.key"));
        privateKeysBobIMidtenAvMangeAlice.add(getPrivateKeyResource("/alice.key"));
        privateKeysBobIMidtenAvMangeAlice.add(getPrivateKeyResource("/alice.key"));
        privateKeysBobIMidtenAvMangeAlice.add(getPrivateKeyResource("/alice.key"));
        privateKeysBobIMidtenAvMangeAlice.add(getPrivateKeyResource("/alice.key"));
        privateKeysBobIMidtenAvMangeAlice.add(getPrivateKeyResource("/alice.key"));
        privateKeysBobIMidtenAvMangeAlice.add(getPrivateKeyResource("/alice.key"));
        privateKeysBobIMidtenAvMangeAlice.add(getPrivateKeyResource("/alice.key"));
        privateKeysBobIMidtenAvMangeAlice.add(getPrivateKeyResource("/alice.key"));

        final AsicHandler asicHandlerAliceFirst = AsicHandler.builder()
            .withPrivateNokkeler(privateKeysAliceFirst)
            .withKeyStoreHolder(getKeystoreHolder())
            .withExecutorService(executor)
            .build();

        final AsicHandler asicHandlerBobFirst = AsicHandler.builder()
            .withPrivateNokkeler(privateKeysBobFirst)
            .withKeyStoreHolder(getKeystoreHolder())
            .withExecutorService(executor)
            .build();

        final AsicHandler asicHandlerBobInMiddleOfAlices = AsicHandler.builder()
            .withPrivateNokkeler(privateKeysBobFirst)
            .withKeyStoreHolder(getKeystoreHolder())
            .withExecutorService(executor)
            .build();

        byte[] payload = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
        InputStream encrypted = asicHandlerAliceFirst.encrypt(getPublicCertResource("bob.cert"), singletonList(new StreamContent(new ByteArrayInputStream(payload), "payload.txt")));
        ZipInputStream decryptAliceFirst = asicHandlerAliceFirst.decrypt(new ByteArrayInputStream(IOUtils.toByteArray(encrypted)));
        ZipInputStream decryptBobFirst = asicHandlerBobFirst.decrypt(new ByteArrayInputStream(IOUtils.toByteArray(encrypted)));
        ZipInputStream decryptBobInMiddleOfAlices = asicHandlerBobInMiddleOfAlices.decrypt(new ByteArrayInputStream(IOUtils.toByteArray(encrypted)));

        assertArrayEquals(null, readBytes(decryptAliceFirst).get("payload.txt"));
        assertArrayEquals(null, readBytes(decryptBobFirst).get("payload.txt"));
        assertArrayEquals(null, readBytes(decryptBobInMiddleOfAlices).get("payload.txt"));
        decryptAliceFirst.close();
        decryptBobFirst.close();
        decryptBobInMiddleOfAlices.close();
        encrypted.close();
        executor.shutdownNow();
    }

    @Test
    @DisplayName("Test at vi kan dekryptere en payload til en fil")
    void testDekrypterFil(@TempDir Path tempDir) throws Exception {

        final ExecutorService executor = Executors.newFixedThreadPool(2);

        final AsicHandler asicHandler = AsicHandler.builder().withPrivatNokkel(getPrivateKeyResource("/bob.key"))
            .withExecutorService(executor)
            .withKeyStoreHolder(getKeystoreHolder())
            .build();

        byte[] payload = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
        InputStream encrypted = asicHandler.encrypt(getPublicCertResource("bob.cert"), singletonList(new StreamContent(new ByteArrayInputStream(payload), "payload.txt")));

        Path path = tempDir.resolve(UUID.randomUUID().toString());

        asicHandler.writeDecrypted(encrypted, path);
        assertTrue(Files.exists(path));
        assertArrayEquals(payload, readBytes(new ZipInputStream(Files.newInputStream(path))).get("payload.txt"));
        executor.shutdownNow();
    }

    @DisplayName("Kan ikke dekryptere uten at privat nikkel er oppgitt")
    @Test
    void testDekrypterPrivatNokkelMangler() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        final ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            final AsicHandler asicHandler = AsicHandler.builder()
                .withExecutorService(executor)
                .withKeyStoreHolder(getKeystoreHolder())
                .build();
            assertThrows(IllegalStateException.class, () -> asicHandler.decrypt(new NullInputStream(1L)));
            assertThrows(IllegalStateException.class, () -> asicHandler.writeDecrypted(new NullInputStream(1), null), AsicHandlerImpl.ERROR_MISSING_PRIVATE_KEY);
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    @DisplayName("Test at vi kan dekryptere mange streams samtidig")
    void testDekrypterStreamMultiThread() throws Exception {

        final int threads = 30;
        CountDownLatch latch = new CountDownLatch(1);
        AtomicBoolean running = new AtomicBoolean();
        AtomicInteger overlaps = new AtomicInteger();

        final ExecutorService executor = Executors.newFixedThreadPool(threads);

        final AsicHandler asicHandler = AsicHandler.builder()
            .withPrivatNokkel(getPrivateKeyResource("/bob.key"))
            .withKeyStoreHolder(getKeystoreHolder())
            .withExecutorService(executor)
            .build();


        Collection<CompletableFuture<Boolean>> futures =
            new ArrayList<>(threads);

        for (int t = 0; t < threads; ++t) {
            futures.add(CompletableFuture.supplyAsync(
                () -> {
                    try {
                        latch.await();
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                    if (running.get()) {
                        overlaps.incrementAndGet();
                    }
                    running.set(true);
                    byte[] payload = UUID.randomUUID().toString().getBytes();

                    try {
                        InputStream encrypt = asicHandler.encrypt(getPublicCertResource("bob.cert"), singletonList(new StreamContent(new ByteArrayInputStream(payload), "payload.txt")));
                        ZipInputStream decrypt = asicHandler.decrypt(new ByteArrayInputStream(IOUtils.toByteArray(encrypt)));
                        log.info("test thread done");
                        boolean arrayEquals = Arrays.equals(payload, readBytes(decrypt).get("payload.txt"));
                        running.set(false);
                        return arrayEquals;
                    } catch (IOException e) {
                        throw new RuntimeException();
                    }
                }
            ));
        }

        latch.countDown();

        assertTrue(CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
            .thenApply(future -> futures.stream()
                .map(CompletableFuture::join)
                .collect(Collectors.toList())).get().stream()
            .allMatch(p -> p));

        assertTrue(overlaps.get() > 0);
        executor.shutdownNow();
    }

    private KeystoreHolder getKeystoreHolder() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        return KeystoreHolder.builder().withKeyAlias("et alias")
            .withKeyPassword("PASSWORD")
            .withKeyStorePassword("PASSWORD")
            .withKeyStore(getKeyStore())
            .build();
    }

    private KeyStore getKeyStore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(this.getClass().getClassLoader().getResourceAsStream("alice-virksomhetssertifikat.p12"), "PASSWORD".toCharArray());
        return keyStore;
    }

    private Map<String, byte[]> readBytes(ZipInputStream dekryptertPayload) throws IOException {
        TreeMap<String, byte[]> files = new TreeMap<>();
        ZipEntry entry;
        byte[] buffer = new byte[2048];
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        while ((entry = dekryptertPayload.getNextEntry()) != null) {
            int len;
            while ((len = dekryptertPayload.read(buffer)) != -1) {
                output.write(buffer, 0, len);
            }
            files.put(entry.getName(), output.toByteArray());
        }
        return files;
    }

    private X509Certificate getPublicCertResource(String filename) {
        try {
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            try (final InputStream certificateStream = getClass().getResourceAsStream("/" + filename)) {
                return (X509Certificate) fact.generateCertificate(certificateStream);
            }
        } catch (IOException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    private PrivateKey getPrivateKeyResource(String filename) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            PrivateKeyInfo o = (PrivateKeyInfo) new PEMParser(new StringReader(IOUtils.resourceToString(filename, Charset.defaultCharset()))).readObject();
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(o.getEncoded()));
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

}