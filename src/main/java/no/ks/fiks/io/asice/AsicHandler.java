package no.ks.fiks.io.asice;

import no.ks.fiks.io.asice.model.Content;

import java.io.InputStream;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.zip.ZipInputStream;

/**
 * Handles creation, validation, encryption and decryption of AsicE packages
 */
public interface AsicHandler extends AutoCloseable {
    static AsicHandlerBuilder builder() {
        return AsicHandlerBuilder.create();
    }

    InputStream encrypt(X509Certificate mottakerCert, List<Content> payload);

    ZipInputStream decrypt(InputStream encryptedAsicData);

    void writeDecrypted(InputStream encryptedAsicData, Path targetPath);
}
