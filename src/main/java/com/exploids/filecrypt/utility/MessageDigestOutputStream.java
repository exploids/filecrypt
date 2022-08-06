package com.exploids.filecrypt.utility;

import java.security.MessageDigest;

/**
 * @author Luca Selinski
 */
public class MessageDigestOutputStream extends ConsumingOutputStream<byte[]> {
    private final MessageDigest messageDigest;
    private byte[] digest;

    public MessageDigestOutputStream(MessageDigest messageDigest) {
        this.messageDigest = messageDigest;
    }

    @Override
    public void write(int b) {
        messageDigest.update((byte) b);
    }

    @Override
    public void write(byte[] b) {
        messageDigest.update(b);
    }

    @Override
    public void write(byte[] b, int off, int len) {
        messageDigest.update(b, off, len);
    }

    @Override
    public void close() {
        digest = messageDigest.digest();
    }

    @Override
    public byte[] getResult() {
        return digest;
    }
}
