package no.ks.fiks.io.asice.write;

import no.ks.fiks.io.asice.model.Content;

import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.List;

public interface EncryptedAsicWriter {

    InputStream createAndEncrypt(X509Certificate x509Certificate, List<Content> contents);

    void close();
}
