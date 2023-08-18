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
    /**
     * Creates a new AsicHandlerBuilder
     * @return a new AsicHandlerBuilder
     */
    static AsicHandlerBuilder builder() {
        return AsicHandlerBuilder.create();
    }

    /**
     * Encrypts the payload using the given certificate
     * @param mottakerCert the certificate to encrypt with
     * @param payload the payload to encrypt
     * @return an inputstream containing the encrypted payload
     */
    InputStream encrypt(X509Certificate mottakerCert, List<Content> payload);

    /**
     * Decryptes the given asic-e package
     * @param encryptedAsicData the asic-e package to decrypt
     * @return an inputstream containing the decrypted payload
     */
    ZipInputStream decrypt(InputStream encryptedAsicData);

    /**
     * Decryptes the given asic-e package and writes the decrypted payload to the given path
     * @param encryptedAsicData the asic-e package to decrypt
     * @param targetPath the path to write the decrypted payload to
     */
    void writeDecrypted(InputStream encryptedAsicData, Path targetPath);
}
