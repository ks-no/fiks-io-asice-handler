package no.ks.fiks.io.asice.crypto;

import lombok.NonNull;
import no.ks.fiks.io.asice.util.CMSKrypteringHandler;
import java.io.BufferedInputStream;
import java.io.InputStream;
import java.security.PrivateKey;
import java.util.List;


public class DecryptionStreamServiceImpl implements DecryptionStreamService {
    private final CMSKrypteringHandler cmsKrypteringHandler = new CMSKrypteringHandler();
    @Override
    public InputStream decrypterStream(@NonNull InputStream encryptedStream, @NonNull List<PrivateKey> privateKeys) {
        if(!encryptedStream.markSupported()){
            return cmsKrypteringHandler.handleEncryptedStream(new BufferedInputStream(encryptedStream), privateKeys);
        }
        else{
            return cmsKrypteringHandler.handleEncryptedStream(encryptedStream,privateKeys);
        }
    }

}
