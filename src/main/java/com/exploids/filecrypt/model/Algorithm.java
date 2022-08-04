package com.exploids.filecrypt.model;

/**
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

    Algorithm(boolean stream) {
        this.stream = stream;
    }

    private final boolean stream;

    /**
     * Returns, whether this is a stream cipher.
     *
     * @return true, if this is a stream cipher
     */
    public boolean isStream() {
        return stream;
    }
}
