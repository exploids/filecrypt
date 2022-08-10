package com.exploids.filecrypt.model;

/**
 * A cipher algorithm.
 *
 * @author Luca Selinski
 */
public enum Algorithm {
    /**
     * Advanced Encryption Standard.
     */
    AES(false),

    /**
     * Rijndael.
     */
    RIJNDAEL(false),

    /**
     * Rivest Cipher 4.
     */
    ARC4(true);

    /**
     * Whether the cipher is a stream cipher.
     */
    private final boolean stream;

    /**
     * Instantiates a new enum constant.
     *
     * @param stream whether the cipher is a stream cipher
     */
    Algorithm(boolean stream) {
        this.stream = stream;
    }

    /**
     * Returns, whether this is a stream cipher.
     *
     * @return true, if this is a stream cipher
     */
    public boolean isStream() {
        return stream;
    }
}
