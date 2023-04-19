package no.ks.fiks.io.asice.util;

import no.ks.kryptering.CMSKrypteringImpl;
import no.ks.kryptering.KrypteringException;

import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.util.List;

public class CMSKrypteringHandler {
    private final CMSKrypteringImpl cmsKryptering = new CMSKrypteringImpl();

    public InputStream handleEncryptedStream(InputStream inputStream, List<PrivateKey> privateKeys){
        InputStream res = null;
        int it = 0;
        inputStream.mark(0);
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
