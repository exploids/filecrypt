package com.exploids.filecrypt.utility;

import javax.crypto.Mac;

/**
 * An output stream that feeds all bytes to a MAC.
 *
 * @author Luca Selinski
 */
public class MacOutputStream extends ConsumingOutputStream<byte[]> {
    /**
     * The MAC calculation.
     */
    private final Mac mac;

    /**
     * The final MAC.
     */
    private byte[] digest;

    /**
     * Creates a new MAC output stream.
     *
     * @param mac the MAC calculation
     */
    public MacOutputStream(Mac mac) {
        this.mac = mac;
    }

    /**
     * Updates the MAC.
     *
     * @param b the byte
     */
    @Override
    public void write(int b) {
        mac.update((byte) b);
    }

    /**
     * Updates the MAC.
     *
     * @param b the data
     */
    @SuppressWarnings("NullableProblems")
    @Override
    public void write(byte[] b) {
        mac.update(b);
    }

    /**
     * Updates the MAC.
     *
     * @param b   the data
     * @param off the start offset in the data
     * @param len the number of bytes to write
     */
    @SuppressWarnings("NullableProblems")
    @Override
    public void write(byte[] b, int off, int len) {
        mac.update(b, off, len);
    }

    /**
     * Completes the MAC calculation.
     */
    @Override
    public void close() {
        digest = mac.doFinal();
    }

    /**
     * Gets the final MAC.
     *
     * @return the final MAC
     */
    @Override
    public byte[] getResult() {
        return digest;
    }
}
