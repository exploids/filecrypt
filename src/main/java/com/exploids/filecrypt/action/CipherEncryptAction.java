package com.exploids.filecrypt.action;

import com.exploids.filecrypt.SecurityCheck;
import com.exploids.filecrypt.exception.InsecureException;
import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Parameters;
import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

/**
 * Encrypts files.
 *
 * @author Luca Selinski
 */
public class CipherEncryptAction extends BasicAction {
    /**
     * The logger for this class.
     */
    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Creates a new encrypt action.
     *
     * @param parameters the command line parameters
     * @param metadata   the metadata
     * @param cipher     the cipher to use
     * @param cipherKey  the key to use
     */
    public CipherEncryptAction(Parameters parameters, Metadata metadata, Cipher cipher, SecretKey cipherKey) {
        super(parameters, metadata, cipher, cipherKey);
    }

    @Override
    public void begin() throws InsecureException {
        var check = new SecurityCheck();
        var concerns = check.check(metadata);
        if (!concerns.isEmpty()) {
            logger.warn("The following parameters are considered insecure: {}", concerns);
            if (!parameters.isInsecureAllowed()) {
                throw new InsecureException(concerns);
            }
        }
    }

    @Override
    public OutputStream call(OutputStream stream) throws GeneralSecurityException {
        var algorithm = metadata.getCipherAlgorithm();
        var key = cipherKey;
        if (key == null) {
            logger.debug("Creating {} key generator…", algorithm);
            var keyGenerator = KeyGenerator.getInstance(algorithm.toString(), "BC");
            if (metadata.getKeySize() > 0) {
                keyGenerator.init(metadata.getKeySize());
            }
            logger.debug("Generating {} key…", algorithm);
            key = keyGenerator.generateKey();
            var encoded = key.getEncoded();
            metadata.setKeySize(encoded.length * 8);
            logger.debug("Generated {} bit key", encoded.length * 8);
            parameters.getKeyData().setCipherKey(ByteBuffer.wrap(encoded));
        }
        cipher.init(Cipher.ENCRYPT_MODE, key);
        logger.debug("Initialized cipher");
        return new CipherOutputStream(stream, cipher);
    }
}
