package com.exploids.filecrypt;

/**
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

    private final String name;

    Padding(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
