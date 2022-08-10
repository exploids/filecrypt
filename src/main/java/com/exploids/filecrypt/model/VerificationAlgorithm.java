package com.exploids.filecrypt.model;

/**
 * A verification algorithm.
 * This includes MAC and hash algorithms.
 *
 * @author Luca Selinski
 */
public enum VerificationAlgorithm {
    /**
     * The SHA256 hash.
     */
    SHA256(null),

    /**
     * The AES CMAC.
     */
    @SuppressWarnings("SpellCheckingInspection")
    AESCMAC("AES"),

    /**
     * The SHA256 HMAC.
     */
    @SuppressWarnings("SpellCheckingInspection")
    HMACSHA256("HMACSHA256");

    /**
     * The algorithm name used for key generation, or null if no key is required.
     */
    private final String keyAlgorithmName;

    /**
     * Instantiates a new enum constant.
     *
     * @param keyAlgorithmName the algorithm name used for key generation, or null if no key is required
     */
    VerificationAlgorithm(String keyAlgorithmName) {
        this.keyAlgorithmName = keyAlgorithmName;
    }

    /**
     * Gets the algorithm name used for key generation.
     *
     * @return the algorithm name used for key generation, or null if no key is required
     */
    public String getKeyAlgorithmName() {
        return keyAlgorithmName;
    }
}
