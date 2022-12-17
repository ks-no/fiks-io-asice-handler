package no.ks.fiks.io.asice.read;

import com.google.common.base.Preconditions;
import lombok.NonNull;
import no.difi.asic.AsicReader;
import no.difi.asic.AsicReaderFactory;
import no.difi.asic.SignatureMethod;
import no.ks.fiks.io.asice.crypto.DecryptionStreamService;
import no.ks.kryptering.CMSKrypteringImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.io.Closeables.closeQuietly;

public class EncryptedAsicReaderImpl implements EncryptedAsicReader {
    private static final Logger log = LoggerFactory.getLogger(EncryptedAsicReaderImpl.class);
    private final ExecutorService executorService;
    private final DecryptionStreamService decryptionStreamService;
    private final AsicReaderFactory asicReaderFactory = AsicReaderFactory.newFactory(SignatureMethod.CAdES);

    public EncryptedAsicReaderImpl(final ExecutorService executorService, final DecryptionStreamService decryptionStreamService) {
        checkNotNull(executorService);
        this.executorService = executorService;
        checkNotNull(decryptionStreamService);
        this.decryptionStreamService = decryptionStreamService;
    }

    @Override
    public ZipInputStream decrypt(final InputStream encryptedAsicData, final PrivateKey privateKey) {
        checkNotNull(encryptedAsicData);
        checkNotNull(privateKey);
        try {
            PipedOutputStream out = new PipedOutputStream();
            PipedInputStream pipedInputStream = new PipedInputStream(out);
            final Map<String, String> mdc = MDC.getCopyOfContextMap();
            executorService.execute(() -> {
                Optional.ofNullable(mdc).ifPresent(MDC::setContextMap);
                try (ZipOutputStream zipOutputStream = new ZipOutputStream(new BufferedOutputStream(out))) {
                    decrypt(encryptedAsicData, zipOutputStream, privateKey);
                } catch (IOException e) {
                    log.error("Failed to decrypt stream", e);
                    throw new RuntimeException(e);
                } finally {
                    MDC.clear();
                }
            });

            return new ZipInputStream(pipedInputStream);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void writeDecryptedToPath(InputStream encryptedAsicData, PrivateKey privateKey, Path targetPath) {
        Preconditions.checkNotNull(encryptedAsicData);
        Preconditions.checkNotNull(privateKey);
        Preconditions.checkNotNull(targetPath);
        try (OutputStream fileStream = Files.newOutputStream(targetPath);
             ZipOutputStream zipOutputStream = new ZipOutputStream(fileStream)) {
            decrypt(encryptedAsicData, privateKey, zipOutputStream);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void decrypt(final InputStream encryptedAsic, final PrivateKey privateKey, final ZipOutputStream zipOutputStream) {
        CMSKrypteringImpl cmsKryptering = new CMSKrypteringImpl();

        InputStream inputStream = cmsKryptering.dekrypterData(encryptedAsic, privateKey);
        decryptElementer(encryptedAsic, zipOutputStream, inputStream);
    }

    private void decryptElementer(InputStream encryptedAsic, ZipOutputStream zipOutputStream, InputStream inputStream) {
        AsicReader reader;

        try {
            reader = asicReaderFactory.open(inputStream);

            boolean entryAdded = false;
            String filnavn;
            while ((filnavn = reader.getNextFile()) != null) {
                entryAdded = true;
                zipOutputStream.putNextEntry(new ZipEntry(filnavn));
                reader.writeFile(zipOutputStream);
                zipOutputStream.closeEntry();
            }

            if (!entryAdded)
                throw new RuntimeException("No entries in asic!");
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            closeQuietly(encryptedAsic);
        }
    }

    private void decrypt(@NonNull final InputStream encryptedAsic,
                         @NonNull final ZipOutputStream zipOutputStream,
                         @NonNull final PrivateKey privatNokkel) {

        checkNotNull(encryptedAsic);
        checkNotNull(zipOutputStream);
        checkNotNull(privatNokkel);
        InputStream inputStream = decryptionStreamService.decrypterStream(encryptedAsic, privatNokkel);
        decryptElementer(encryptedAsic, zipOutputStream, inputStream);
    }
}
