package com.exploids.filecrypt.action;

import com.exploids.filecrypt.exception.MissingMacKeyException;
import com.exploids.filecrypt.exception.VerificationFailedException;
import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Parameters;
import com.exploids.filecrypt.utility.ConsumingOutputStream;
import com.exploids.filecrypt.utility.FileCleanup;
import com.exploids.filecrypt.utility.MacOutputStream;
import com.exploids.filecrypt.utility.MessageDigestOutputStream;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.output.TeeOutputStream;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

/**
 * Checks MACs/hashes of files.
 *
 * @author Luca Selinski
 */
public class VerificationCheckAction extends BasicAction {
    /**
     * The logger for this class.
     */
    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * The MAC/hash calculator.
     */
    private ConsumingOutputStream<byte[]> verificationCalculator;

    /**
     * Creates a new verification check action.
     *
     * @param parameters the command line parameters
     * @param metadata   the metadata
     * @param cipher     the cipher to use
     * @param cipherKey  the key to use
     */
    public VerificationCheckAction(Parameters parameters, Metadata metadata, Cipher cipher, SecretKey cipherKey) {
        super(parameters, metadata, cipher, cipherKey);
    }

    @Override
    public OutputStream call(OutputStream stream) throws GeneralSecurityException, MissingMacKeyException {
        var verificationAlgorithm = metadata.getVerificationAlgorithm();
        if (verificationAlgorithm.getKeyAlgorithmName() == null) {
            logger.debug("Selected verification algorithm {} is a message digest", verificationAlgorithm);
            var messageDigest = MessageDigest.getInstance(verificationAlgorithm.toString(), "BC");
            verificationCalculator = new MessageDigestOutputStream(messageDigest);
        } else {
            logger.debug("Selected verification algorithm {} is a MAC", verificationAlgorithm);
            var macKeyBytes = parameters.getKeyData().getVerificationKey();
            if (macKeyBytes == null) {
                logger.debug("Missing MAC key");
                throw new MissingMacKeyException();
            }
            var macKey = new SecretKeySpec(macKeyBytes.array(), verificationAlgorithm.getKeyAlgorithmName());
            var mac = Mac.getInstance(verificationAlgorithm.toString(), "BC");
            mac.init(macKey);
            verificationCalculator = new MacOutputStream(mac);
        }
        return new TeeOutputStream(stream, verificationCalculator);
    }

    @Override
    public void end(ObjectMapper mapper, FileCleanup cleanup) throws VerificationFailedException {
        var expected = metadata.getVerification().array();
        var actual = verificationCalculator.getResult();
        if (Arrays.areEqual(expected, actual)) {
            logger.debug("The MAC/hash {} seems to be valid", Hex.toHexString(verificationCalculator.getResult()));
        } else {
            throw new VerificationFailedException(expected, actual);
        }
    }
}
