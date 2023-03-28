package no.ks.fiks.io.asice.crypto;

import lombok.NonNull;
import no.ks.kryptering.CMSKrypteringImpl;
import no.ks.kryptering.KrypteringException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.security.PrivateKey;
import java.util.List;

public class DecryptionStreamServiceImpl implements DecryptionStreamService {
    private static final Logger log = LoggerFactory.getLogger(DecryptionStreamServiceImpl.class);

    private final CMSKrypteringImpl cmsKryptering = new CMSKrypteringImpl();

    @Override
    public InputStream decrypterStream(@NonNull InputStream encryptedStream, @NonNull List<PrivateKey> privateKeys) {
        for (int i = 0; i < privateKeys.size(); i++) {
            try {
                return cmsKryptering.dekrypterData(encryptedStream, privateKeys.get(i));
            } catch (KrypteringException krypteringException) {
                if (i == privateKeys.size() - 1)
                    throw krypteringException;
                else log.info("HHH");
            }
        }
        return null;
    }
}
