package com.exploids.filecrypt;

import com.exploids.filecrypt.model.Algorithm;
import com.exploids.filecrypt.model.BlockMode;
import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.PasswordAlgorithm;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
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
    private final int minimumGenerationTime = 3000;

    /**
     * Generates a key from a password.
     *
     * @param password the password
     * @param metadata the metadata
     * @return the key
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeySpecException
     */
    public SecretKey generate(char[] password, Metadata metadata) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        var passwordAlgorithm = metadata.getPasswordAlgorithm();
        var keySize = metadata.getKeySize();
        var name = algorithmName(passwordAlgorithm, keySize, metadata.getCipherAlgorithm(), metadata.getBlockMode());
        var factory = SecretKeyFactory.getInstance(name, "BC");
        SecretKey key;
        var cost = metadata.getPasswordCost();
        logger.info("Generating parameters for password based encryption. This will take a moment.");
        if (cost == null) {
            cost = 1024;
            boolean tooFast = true;
            do {
                logger.debug("Testing a cost factor of {}.", cost);
                var startTime = System.currentTimeMillis();
                key = lol(password, cost, metadata, factory);
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
            key = lol(password, cost, metadata, factory);
            var duration = System.currentTimeMillis() - startTime;
            if (duration < minimumGenerationTime) {
                logger.warn("The password cost factor seems too low. Please choose a higher cost factor to ensure secure encryption.");
            }
        }
        logger.info("All parameters have been generated.");
        return key;
    }

    private SecretKey lol(char[] password, int cost, Metadata metadata, SecretKeyFactory factory) throws InvalidKeySpecException {
        var keySize = metadata.getKeySize();
        var salt = metadata.getPasswordSalt().array();
        if (metadata.getPasswordAlgorithm() == PasswordAlgorithm.SCRYPT) {
            return factory.generateSecret(new ScryptKeySpec(password, salt, cost, metadata.getPasswordBlockSize(), metadata.getPasswordParallelization(), keySize));
        } else {
            return factory.generateSecret(new PBEKeySpec(password, salt, cost, keySize));
        }
    }

    /**
     * Builds the algorithm name for bouncy castle.
     *
     * @param passwordAlgorithm the password algorithm
     * @param keySize           the key size
     * @param cipherAlgorithm   the cipher algorithm
     * @param blockMode         the cipher block mode
     * @return the algorithm name
     */
    private String algorithmName(PasswordAlgorithm passwordAlgorithm, int keySize, Algorithm cipherAlgorithm, BlockMode blockMode) {
        if (passwordAlgorithm == PasswordAlgorithm.SCRYPT) {
            return "SCRYPT";
        } else if (cipherAlgorithm.isStream()) {
            return String.format("PBEWith%sAnd%dBit%s", passwordAlgorithm, keySize, cipherAlgorithm);
        } else {
            return String.format("PBEWith%sAnd%dBit%s-%s-BC", passwordAlgorithm, keySize, cipherAlgorithm, blockMode);
        }
    }
}
