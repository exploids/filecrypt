package com.exploids.filecrypt.model;

/**
 * A block padding mode.
 *
 * @author Luca Selinski
 */
public enum Padding {
    /**
     * NoPadding.
     */
    NO("NoPadding"),

    /**
     * PKCS7Padding.
     */
    PKCS7("PKCS7Padding"),

    /**
     * ZeroBytePadding.
     */
    ZERO_BYTE("ZeroBytePadding");

    private final String algorithmName;

    Padding(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    /**
     * Gets the name of this padding.
     *
     * @return the name
     */
    public String getAlgorithmName() {
        return algorithmName;
    }
}
