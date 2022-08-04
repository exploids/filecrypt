package com.exploids.filecrypt.model;

/**
 * @author Luca Selinski
 */
public enum VerificationAlgorithm {
    SHA256(null),
    AESCMAC("AES"),
    HMACSHA256("HMACSHA256");

    private final String keyAlgorithmName;

    VerificationAlgorithm(String keyAlgorithmName) {
        this.keyAlgorithmName = keyAlgorithmName;
    }

    /**
     * Gets the key algorithm name of this mac algorithm.
     *
     * @return the key algorithm name
     */
    public String getKeyAlgorithmName() {
        return keyAlgorithmName;
    }
}
