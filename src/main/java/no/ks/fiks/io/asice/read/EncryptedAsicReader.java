package no.ks.fiks.io.asice.read;

import java.io.InputStream;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.List;
import java.util.zip.ZipInputStream;

public interface EncryptedAsicReader {

    ZipInputStream decrypt(InputStream encryptedAsicData, List<PrivateKey> privateKeys);

    void writeDecryptedToPath(final InputStream encryptedAsicData, List<PrivateKey> privateKeys, Path targetPath);
}
