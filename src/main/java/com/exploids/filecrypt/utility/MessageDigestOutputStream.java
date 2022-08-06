package com.exploids.filecrypt.utility;

import java.io.IOException;
import java.security.MessageDigest;

/**
 * @author Luca Selinski
 */
public class MessageDigestOutputStream extends VerificationCalculator {
    private final MessageDigest messageDigest;
    private byte[] digest;

    public MessageDigestOutputStream(MessageDigest messageDigest) {
        this.messageDigest = messageDigest;
    }

    @Override
    public void write(int b) throws IOException {
        messageDigest.update((byte) b);
    }

    @Override
    public void write(byte[] b) throws IOException {
        messageDigest.update(b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        messageDigest.update(b, off, len);
    }

    @Override
    public void close() throws IOException {
        digest = messageDigest.digest();
    }

    @Override
    public byte[] getEncoded() {
        return digest;
    }
}
