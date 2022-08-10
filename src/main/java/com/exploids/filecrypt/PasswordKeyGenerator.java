package com.exploids.filecrypt;

import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.PasswordAlgorithm;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.spec.InvalidKeySpecException;

/**
 * Generates keys from passwords.
 *
 * @author Luca Selinski
 */
public class PasswordKeyGenerator {
    /**
     * The logger for this class.
     */
    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * The minimum time that should be required to generate a key in ms.
     */
    private final int minimumGenerationTime;

    /**
     * Creates a new password key generator.
     *
     * @param minimumGenerationTime the minimum time that should be required to generate a key in ms
     */
    public PasswordKeyGenerator(int minimumGenerationTime) {
        this.minimumGenerationTime = minimumGenerationTime;
    }

    /**
     * Generates a key from a password.
     *
     * @param password      the password
     * @param algorithmName the cipher name
     * @param metadata      the metadata
     * @return the key
     * @throws GeneralSecurityException if some parameters are invalid
     */
    public SecretKey generate(char[] password, String algorithmName, Metadata metadata) throws GeneralSecurityException {
        var factory = SecretKeyFactory.getInstance(algorithmName, "BC");
        SecretKey key;
        var cost = metadata.getPasswordCost();
        logger.info("Generating parameters for password based encryption. This will take a moment.");
        if (cost == null) {
            cost = 1024;
            boolean tooFast = true;
            do {
                logger.debug("Testing a cost factor of {}.", cost);
                var startTime = System.currentTimeMillis();
                key = generateKey(password, cost, metadata, factory);
                var duration = System.currentTimeMillis() - startTime;
                logger.debug("Took {} ms.", duration);
                if (duration < minimumGenerationTime) {
                    var targetTime = minimumGenerationTime << 1;
                    for (int i = 8; i >= 0; i--) {
                        if (duration < targetTime >> i) {
                            cost <<= i;
                            break;
                        }
                    }
                } else {
                    tooFast = false;
                }
            } while (tooFast);
            metadata.setPasswordCost(cost);
        } else {
            var startTime = System.currentTimeMillis();
            key = generateKey(password, cost, metadata, factory);
            var duration = System.currentTimeMillis() - startTime;
            if (duration < minimumGenerationTime) {
                logger.warn("The password cost factor seems too low. Please choose a higher cost factor to ensure secure encryption.");
            }
        }
        logger.info("All parameters have been generated.");
        return key;
    }

    /**
     * Produces a key using the given cost factor.
     *
     * @param password the password
     * @param cost     the cost factor
     * @param metadata the metadata
     * @param factory  the key factory
     * @return the key
     * @throws InvalidKeySpecException if some parameters are invalid
     */
    private SecretKey generateKey(char[] password, int cost, Metadata metadata, SecretKeyFactory factory) throws InvalidKeySpecException {
        var keySize = metadata.getKeySize();
        var salt = metadata.getPasswordSalt().array();
        if (metadata.getPasswordAlgorithm() == PasswordAlgorithm.SCRYPT) {
            return factory.generateSecret(new ScryptKeySpec(password, salt, cost, metadata.getPasswordBlockSize(), metadata.getPasswordParallelization(), keySize));
        } else {
            return factory.generateSecret(new PBEKeySpec(password, salt, cost, keySize));
        }
    }
}
