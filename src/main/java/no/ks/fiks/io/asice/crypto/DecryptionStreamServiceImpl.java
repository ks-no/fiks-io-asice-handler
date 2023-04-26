package no.ks.fiks.io.asice.crypto;

import lombok.NonNull;
import no.ks.fiks.io.asice.util.CMSKrypteringHandler;
import java.io.InputStream;
import java.security.PrivateKey;
import java.util.List;
import static com.google.common.base.Preconditions.checkNotNull;


public class DecryptionStreamServiceImpl implements DecryptionStreamService {
    private final CMSKrypteringHandler cmsKrypteringHandler = new CMSKrypteringHandler();
    @Override
    public InputStream decrypterStream(@NonNull InputStream encryptedStream, @NonNull List<PrivateKey> privateKeys) {
        checkNotNull(privateKeys.get(0));
        return cmsKrypteringHandler.handleEncryptedStream(encryptedStream,privateKeys);
    }
}
