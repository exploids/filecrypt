package com.exploids.filecrypt;

import com.exploids.filecrypt.model.Algorithm;
import com.exploids.filecrypt.model.BlockMode;
import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Padding;
import com.exploids.filecrypt.model.PasswordAlgorithm;
import com.exploids.filecrypt.model.VerificationAlgorithm;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * Generates default encryption parameters.
 *
 * @author Luca Selinski
 */
public class DefaultParameterGenerator {
    /**
     * Generates default encryption parameters.
     *
     * @param metadata      the metadata
     * @param passwordBased whether password based encryption is used
     * @throws GeneralSecurityException if incorrect parameters are used
     */
    public void generate(Metadata metadata, boolean passwordBased) throws GeneralSecurityException {
        if (metadata.getCipherAlgorithm() == null) {
            metadata.setCipherAlgorithm(Algorithm.AES);
        }
        if (!metadata.getCipherAlgorithm().isStream()) {
            if (metadata.getBlockMode() == null) {
                metadata.setBlockMode(BlockMode.CBC);
            }
            if (metadata.getPadding() == null) {
                if (metadata.getBlockMode() == BlockMode.GCM) {
                    metadata.setPadding(Padding.NONE);
                } else {
                    metadata.setPadding(Padding.PKCS7);
                }
            }
        }
        if (metadata.getKeySize() == null) {
            metadata.setKeySize(256);
        }
        if (metadata.getVerificationAlgorithm() == null && metadata.getVerification() != null) {
            metadata.setVerificationAlgorithm(VerificationAlgorithm.HMACSHA256);
        }
        if (passwordBased) {
            if (metadata.getPasswordAlgorithm() == null) {
                metadata.setPasswordAlgorithm(PasswordAlgorithm.SCRYPT);
            }
            if (metadata.getPasswordSalt() == null) {
                var random = SecureRandom.getInstance("DEFAULT", "BC");
                var salt = new byte[metadata.getPasswordAlgorithm().getSaltSize()];
                random.nextBytes(salt);
                metadata.setPasswordSalt(ByteBuffer.wrap(salt));
            }
            if (metadata.getPasswordAlgorithm() == PasswordAlgorithm.SCRYPT) {
                if (metadata.getPasswordBlockSize() == null) {
                    metadata.setPasswordBlockSize(8);
                }
                if (metadata.getPasswordParallelization() == null) {
                    metadata.setPasswordParallelization(4);
                }
            }
        }
    }
}
