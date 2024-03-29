package com.exploids.filecrypt.model;

/**
 * A cipher block mode.
 *
 * @author Luca Selinski
 */
public enum BlockMode {
    /**
     * The Electronic Code Book mode.
     */
    ECB,

    /**
     * The Cipher Block Chaining mode.
     */
    CBC,

    /**
     * The Counter mode.
     */
    CTR,

    /**
     * The Cipher FeedBack mode.
     */
    CFB,

    /**
     * The Output FeedBack mode.
     */
    OFB,

    /**
     * The Galois/Counter Mode.
     */
    GCM,
}
