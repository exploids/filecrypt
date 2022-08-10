package com.exploids.filecrypt.model;

/**
 * A password based encryption algorithm.
 *
 * @author Luca Selinski
 */
public enum PasswordAlgorithm {
    /**
     * Password based encryption using SHA256.
     */
    SHA256(256 / 8),

    /**
     * Password based encryption using SHA1.
     */
    SHA(160 / 8),

    /**
     * Password based encryption using SCRYPT.
     */
    SCRYPT(256 / 8);

    /**
     * The minimum number of salt bytes.
     */
    private final int saltSize;

    /**
     * Instantiates a new enum constant.
     *
     * @param saltSize the minimum number of salt bytes
     */
    PasswordAlgorithm(int saltSize) {
        this.saltSize = saltSize;
    }

    /**
     * Gets the minimum number of salt bytes.
     *
     * @return the minimum number of salt bytes
     */
    public int getSaltSize() {
        return saltSize;
    }
}
