package no.ks.fiks.io.asice.model;

import java.io.InputStream;

/**
 * Represents a file in an asic-e package
 */
public interface Content {
    /**
     * @return the filename of the file
     */
    String getFilnavn();

    /**
     * @return the contents an inputstream
     */
    InputStream getPayload();
}
