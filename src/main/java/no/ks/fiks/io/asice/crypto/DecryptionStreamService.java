package no.ks.fiks.io.asice.crypto;

import java.io.InputStream;
import java.security.PrivateKey;
import java.util.List;

@FunctionalInterface
public interface DecryptionStreamService {

    InputStream decrypterStream(final InputStream encryptedStream, List<PrivateKey> privateKey);
}
