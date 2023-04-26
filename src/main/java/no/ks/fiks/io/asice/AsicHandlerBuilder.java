package no.ks.fiks.io.asice;

import com.google.common.base.Preconditions;
import no.ks.fiks.io.asice.crypto.DecryptionStreamServiceImpl;
import no.ks.fiks.io.asice.crypto.PipedEncryptionServiceImpl;
import no.ks.fiks.io.asice.model.KeystoreHolder;
import no.ks.fiks.io.asice.read.EncryptedAsicReaderImpl;
import no.ks.fiks.io.asice.sign.SignatureHelperProviderImpl;
import no.ks.fiks.io.asice.write.EncryptedAsicWriterImpl;

import java.security.PrivateKey;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;

/**
 * Convenience class that makes it easier to setup a new {@link AsicHandler}.
 */
public final class AsicHandlerBuilder {
    private static final String MISSING_PROPERTY_FORMAT = "\"%s\" er ikke satt";
    private List<PrivateKey> privateKeys;
    private ExecutorService executorService;
    private KeystoreHolder keystoreHolder;

    private AsicHandlerBuilder() {
    }

    public static AsicHandlerBuilder create() {
        return new AsicHandlerBuilder();
    }

    public AsicHandlerBuilder withPrivatNokkel(PrivateKey privateKey) {
        this.privateKeys = Collections.singletonList(privateKey);
        return this;
    }
    public AsicHandlerBuilder withPrivateNokler(List<PrivateKey> privateKeys) {
        this.privateKeys = privateKeys;
        return this;
    }

    /**
     * Use minimum 2 threads
     * @param executorService Minimum 2 threads
     * @return AsicHandlerBuilder instance
     */
    public AsicHandlerBuilder withExecutorService(final ExecutorService executorService) {
        this.executorService = executorService;
        return this;
    }

    public AsicHandlerBuilder withKeyStoreHolder(final KeystoreHolder keystoreHolder) {
        this.keystoreHolder = keystoreHolder;
        return this;
    }

    public AsicHandler build() {
        Preconditions.checkNotNull(executorService, MISSING_PROPERTY_FORMAT, "executorService");
        Preconditions.checkNotNull(keystoreHolder, MISSING_PROPERTY_FORMAT, "keystoreHolder");
        return new AsicHandlerImpl(privateKeys, new EncryptedAsicWriterImpl(new PipedEncryptionServiceImpl(executorService), executorService, new SignatureHelperProviderImpl(keystoreHolder)), new EncryptedAsicReaderImpl(executorService, new DecryptionStreamServiceImpl()));
    }
}
