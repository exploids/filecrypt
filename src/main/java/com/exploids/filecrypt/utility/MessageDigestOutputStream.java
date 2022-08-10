package com.exploids.filecrypt.utility;

import java.security.MessageDigest;

/**
 * An output stream that feeds all bytes to a message digest.
 *
 * @author Luca Selinski
 */
public class MessageDigestOutputStream extends ConsumingOutputStream<byte[]> {
    /**
     * The message digest calculation.
     */
    private final MessageDigest messageDigest;

    /**
     * The final message digest.
     */
    private byte[] digest;

    /**
     * Creates a new message digest output stream.
     *
     * @param messageDigest the message digest calculation
     */
    public MessageDigestOutputStream(MessageDigest messageDigest) {
        this.messageDigest = messageDigest;
    }

    /**
     * Updates the message digest.
     *
     * @param b the byte
     */
    @Override
    public void write(int b) {
        messageDigest.update((byte) b);
    }

    /**
     * Updates the message digest.
     *
     * @param b the data
     */
    @SuppressWarnings("NullableProblems")
    @Override
    public void write(byte[] b) {
        messageDigest.update(b);
    }

    /**
     * Updates the message digest.
     *
     * @param b   the data
     * @param off the start offset in the data
     * @param len the number of bytes to write
     */
    @SuppressWarnings("NullableProblems")
    @Override
    public void write(byte[] b, int off, int len) {
        messageDigest.update(b, off, len);
    }

    /**
     * Completes the message digest calculation.
     */
    @Override
    public void close() {
        digest = messageDigest.digest();
    }

    /**
     * Gets the final message digest.
     *
     * @return the final message digest
     */
    @Override
    public byte[] getResult() {
        return digest;
    }
}
