package no.ks.fiks.io.asice.util;

import no.ks.fiks.io.asice.read.EncryptedAsicReaderImpl;
import no.ks.kryptering.CMSKrypteringImpl;
import no.ks.kryptering.KrypteringException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.util.List;

public class CMSKrypteringHandler {
    private final CMSKrypteringImpl cmsKryptering = new CMSKrypteringImpl();
    private static final Logger log = LoggerFactory.getLogger(CMSKrypteringHandler.class);


    public InputStream handleEncryptedStream(InputStream inputStream, List<PrivateKey> privateKeys){
        InputStream res = null;
        int it = 0;
        inputStream.mark(0);
        while(res == null && it < privateKeys.size()){
            try {
                res = decrypterStreamForKey(inputStream, privateKeys.get(it));
            } catch (KrypteringException krypteringException){
                if(it == privateKeys.size()-1){
                    throw krypteringException;
                }
                log.info("Kryptering feilet for privatnøkkel nr " + (it+1) + " av " + (privateKeys.size()) + ". Prøver neste nøkkel");
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
