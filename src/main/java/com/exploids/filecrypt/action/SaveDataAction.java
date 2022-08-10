package com.exploids.filecrypt.action;

import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Parameters;
import com.exploids.filecrypt.utility.FileCleanup;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Saves key and meta data.
 *
 * @author Luca Selinski
 */
public class SaveDataAction extends BasicAction {
    /**
     * The logger for this class.
     */
    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Creates a new data saving action.
     *
     * @param parameters the command line parameters
     * @param metadata   the metadata
     * @param cipher     the cipher to use
     * @param cipherKey  the key to use
     */
    public SaveDataAction(Parameters parameters, Metadata metadata, Cipher cipher, SecretKey cipherKey) {
        super(parameters, metadata, cipher, cipherKey);
    }

    @Override
    public void end(ObjectMapper mapper, FileCleanup cleanup) throws IOException {
        logger.debug("Encoding metadata.");
        var iv = cipher.getIV();
        if (iv != null) {
            metadata.setInitializationVector(ByteBuffer.wrap(iv));
        }
        try (var metadataOut = cleanup.newBufferedWriter(parameters.getMetadataFile())) {
            mapper.writeValue(metadataOut, metadata);
        }
        logger.debug("Wrote metadata to {}.", parameters.getMetadataFile().toAbsolutePath());
        var keyData = parameters.getKeyData();
        if (keyData.getCipherKey() != null || keyData.getVerificationKey() != null) {
            logger.debug("Encoding key.");
            try (var keyOut = cleanup.newBufferedWriter(parameters.getKeyFile())) {
                mapper.writeValue(keyOut, parameters.getKeyData());
            }
            logger.debug("Wrote key data to {}.", parameters.getKeyFile().toAbsolutePath());
        } else {
            logger.debug("No key data to write.");
        }
    }
}
