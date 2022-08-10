package com.exploids.filecrypt.model;

/**
 * A block padding mode.
 *
 * @author Luca Selinski
 */
public enum Padding {
    /**
     * No padding at all.
     */
    NONE("NoPadding"),

    /**
     * ISO7816-4 Padding.
     */
    ISO7816_4("ISO7816-4Padding"),

    /**
     * ISO101026-2 Padding.
     */
    ISO10126_2("ISO10126-2Padding"),

    /**
     * PKCS#5/PKCS#7 Padding.
     */
    PKCS7("PKCS7Padding"),

    /**
     * Trailing bit complement padding.
     */
    TBC("TBCPadding"),

    /**
     * X9.23 Padding.
     */
    X9_23("X9.23Padding"),

    /**
     * Zero byte padding.
     */
    ZERO_BYTE("ZeroBytePadding"),

    /**
     * Cipher text stealing.
     */
    CTS("CTSPadding");

    /**
     * The bouncy castle padding name.
     */
    private final String algorithmName;

    /**
     * Creates a new enum constant.
     *
     * @param algorithmName the bouncy castle padding name
     */
    Padding(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    /**
     * Gets the name of this padding.
     *
     * @return the name
     */
    public String getPaddingName() {
        return algorithmName;
    }
}
