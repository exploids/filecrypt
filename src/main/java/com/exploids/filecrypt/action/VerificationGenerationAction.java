package com.exploids.filecrypt.action;

import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Parameters;
import com.exploids.filecrypt.utility.ConsumingOutputStream;
import com.exploids.filecrypt.utility.FileCleanup;
import com.exploids.filecrypt.utility.MacOutputStream;
import com.exploids.filecrypt.utility.MessageDigestOutputStream;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.output.TeeOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

/**
 * Generates MACs/hashes for files.
 *
 * @author Luca Selinski
 */
public class VerificationGenerationAction extends BasicAction {
    /**
     * The logger for this class.
     */
    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * The MAC/hash calculator.
     */
    private ConsumingOutputStream<byte[]> verificationCalculator;

    /**
     * Creates a new verification generation action.
     *
     * @param parameters the command line parameters
     * @param metadata   the metadata
     * @param cipher     the cipher to use
     * @param cipherKey  the key to use
     */
    public VerificationGenerationAction(Parameters parameters, Metadata metadata, Cipher cipher, SecretKey cipherKey) {
        super(parameters, metadata, cipher, cipherKey);
    }

    @Override
    public OutputStream call(OutputStream stream) throws GeneralSecurityException {
        var verificationAlgorithm = metadata.getVerificationAlgorithm();
        if (verificationAlgorithm.getKeyAlgorithmName() == null) {
            logger.debug("Selected verification algorithm {} is a message digest", verificationAlgorithm);
            var messageDigest = MessageDigest.getInstance(verificationAlgorithm.toString(), "BC");
            verificationCalculator = new MessageDigestOutputStream(messageDigest);
        } else {
            logger.debug("Selected verification algorithm {} is a MAC", verificationAlgorithm);
            var keyGenerator = KeyGenerator.getInstance(verificationAlgorithm.getKeyAlgorithmName(), "BC");
            logger.debug("Generating {} key", verificationAlgorithm);
            var macKey = keyGenerator.generateKey();
            parameters.getKeyData().setVerificationKey(ByteBuffer.wrap(macKey.getEncoded()));
            var mac = Mac.getInstance(verificationAlgorithm.toString(), "BC");
            mac.init(macKey);
            verificationCalculator = new MacOutputStream(mac);
        }
        return new TeeOutputStream(stream, verificationCalculator);
    }

    @Override
    public void end(ObjectMapper mapper, FileCleanup cleanup) {
        metadata.setVerification(ByteBuffer.wrap(verificationCalculator.getResult()));
    }
}
