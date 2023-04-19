package no.ks.fiks.io.asice.crypto;

import lombok.NonNull;
import no.ks.kryptering.CMSKrypteringImpl;
import no.ks.kryptering.KrypteringException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.util.List;

public class DecryptionStreamServiceImpl implements DecryptionStreamService {
    private static final Logger log = LoggerFactory.getLogger(DecryptionStreamServiceImpl.class);

    private final CMSKrypteringImpl cmsKryptering = new CMSKrypteringImpl();

    @Override
    public InputStream decrypterStream(@NonNull InputStream encryptedStream, @NonNull List<PrivateKey> privateKeys) {
        if(!encryptedStream.markSupported()){
            return handleEncryptedStream(new BufferedInputStream(encryptedStream), privateKeys);
        }
        else{
            return handleEncryptedStream(encryptedStream,privateKeys);
        }
    }

    private InputStream handleEncryptedStream(InputStream inputStream, List<PrivateKey> privateKeys){
        InputStream res = null;
        int it = 0;
        inputStream.mark(0);
        if(!inputStream.markSupported()){
            inputStream = new BufferedInputStream(inputStream);
        }
        while(res == null && it < privateKeys.size()){
            try {
                res = decrypterStreamForKey(inputStream, privateKeys.get(it));
            } catch (KrypteringException krypteringException){
                try {
                    inputStream.reset();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                it++;
            }
        }
        return res;
    }

    private InputStream decrypterStreamForKey(InputStream inputStream, PrivateKey privateKey) {
        return cmsKryptering.dekrypterData(inputStream, privateKey);
    }
}
