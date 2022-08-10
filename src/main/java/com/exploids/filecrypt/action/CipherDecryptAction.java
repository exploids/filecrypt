package com.exploids.filecrypt.action;

import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Parameters;
import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

/**
 * Decrypts files.
 *
 * @author Luca Selinski
 */
public class CipherDecryptAction extends BasicAction {
    /**
     * The logger for this class.
     */
    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Creates a new decrypt action.
     *
     * @param parameters the command line parameters
     * @param metadata   the metadata
     * @param cipher     the cipher to use
     * @param cipherKey  the key to use
     */
    public CipherDecryptAction(Parameters parameters, Metadata metadata, Cipher cipher, SecretKey cipherKey) {
        super(parameters, metadata, cipher, cipherKey);
    }

    @Override
    public OutputStream call(OutputStream stream) throws GeneralSecurityException {
        logger.debug("Initializing {} cipher", cipher.getAlgorithm());
        var iv = metadata.getInitializationVector();
        if (iv == null) {
            cipher.init(Cipher.DECRYPT_MODE, cipherKey);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, cipherKey, new IvParameterSpec(iv.array()));
        }
        logger.debug("Decrypting file");
        return new CipherOutputStream(stream, cipher);
    }
}
