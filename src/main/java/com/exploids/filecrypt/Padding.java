package com.exploids.filecrypt;

/**
 * @author Luca Selinski
 */
public enum Padding {
    /**
     * NoPadding.
     */
    NO,

    /**
     * PKCS7Padding.
     */
    PKCS7,

    /**
     * ZeroBytePadding.
     */
    ZERO_BYTE,
}
