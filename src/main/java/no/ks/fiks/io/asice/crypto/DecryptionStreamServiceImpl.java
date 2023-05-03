package no.ks.fiks.io.asice.crypto;

import com.google.common.base.Preconditions;
import lombok.NonNull;
import no.ks.fiks.io.asice.util.CMSKrypteringHandler;
import java.io.InputStream;
import java.security.PrivateKey;
import java.util.List;


public class DecryptionStreamServiceImpl implements DecryptionStreamService {
    private final CMSKrypteringHandler cmsKrypteringHandler = new CMSKrypteringHandler();
    static final String ERROR_MISSING_PRIVATE_KEY = "Privatnøkkel er ikke definert. Kan ikke dekryptere";
    @Override
    public InputStream decrypterStream(@NonNull InputStream encryptedStream, @NonNull List<PrivateKey> privateKeys) {
        if(privateKeys.isEmpty()){
            throw new IllegalStateException(ERROR_MISSING_PRIVATE_KEY);
        }
        privateKeys.forEach(Preconditions::checkNotNull);
        return cmsKrypteringHandler.handleEncryptedStream(encryptedStream,privateKeys);
    }
}
