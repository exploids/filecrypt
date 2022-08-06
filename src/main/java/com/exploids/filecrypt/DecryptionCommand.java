package com.exploids.filecrypt;

import com.exploids.filecrypt.exception.InsecureException;
import com.exploids.filecrypt.exception.VerificationFailedException;
import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Parameters;
import com.exploids.filecrypt.utility.MacOutputStream;
import com.exploids.filecrypt.utility.MessageDigestOutputStream;
import com.exploids.filecrypt.utility.VerificationCalculator;
import org.apache.commons.io.output.TeeOutputStream;
import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class DecryptionCommand implements SubCommand {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private Parameters parameters;
    private Cipher cipher;
    private Metadata metadata;
    private VerificationCalculator verificationCalculator;

    @Override
    public String outputBaseName(String baseName) {
        return baseName + "_decrypted";
    }

    @Override
    public String companionBaseName(String baseName) {
        return baseName;
    }

    @Override
    public void init(Parameters parameters, Metadata combinedMetadata, Cipher cipher) {
        this.parameters = parameters;
        this.metadata = combinedMetadata;
        this.cipher = cipher;
    }

    @Override
    public void check() throws InsecureException {
    }

    @Override
    public OutputStream call(OutputStream out) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, VerificationFailedException {
        logger.debug("Decrypting file…");
        var key = new SecretKeySpec(parameters.getKeyData().getCipherKey().array(), metadata.getCipherAlgorithm().toString());
        logger.debug("Initializing {} cipher…", cipher.getAlgorithm());
        var iv = metadata.getInitializationVector();
        if (iv == null) {
            cipher.init(Cipher.DECRYPT_MODE, key);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv.array()));
        }
        logger.debug("Decrypting file…");
        OutputStream wrappedOut = new CipherOutputStream(out, cipher);
        if (metadata.getVerification() != null) {
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
                    throw new VerificationFailedException();
                }
                var macKey = new SecretKeySpec(macKeyBytes.array(), metadata.getVerificationAlgorithm().toString());
                var mac = Mac.getInstance(metadata.getVerificationAlgorithm().toString(), "BC");
                mac.init(macKey);
                verificationCalculator = new MacOutputStream(mac);
            }
            wrappedOut = new TeeOutputStream(wrappedOut, verificationCalculator);
        }
        return wrappedOut;
    }

    @Override
    public void doFinal() throws VerificationFailedException {
        if (verificationCalculator != null) {
            var expected = metadata.getVerification().array();
            var actual = verificationCalculator.getEncoded();
            if (Arrays.areEqual(expected, actual)) {
                logger.debug("The MAC/hash {} seems to be valid", Hex.toHexString(verificationCalculator.getEncoded()));
            } else {
                logger.error("The MAC/hash does not match (expected {}, got {})", Hex.toHexString(expected), Hex.toHexString(actual));
                throw new VerificationFailedException();
            }
        }
    }
}
