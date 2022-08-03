package com.exploids.filecrypt;

import javax.crypto.Mac;
import java.io.IOException;
import java.io.OutputStream;

/**
 * @author Luca Selinski
 */
public class MacOutputStream extends OutputStream {
    private final Mac mac;
    private byte[] digest;

    public MacOutputStream(Mac mac) {
        this.mac = mac;
    }

    @Override
    public void write(int b) throws IOException {
        mac.update((byte) b);
    }

    @Override
    public void write(byte[] b) throws IOException {
        mac.update(b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        mac.update(b, off, len);
    }

    @Override
    public void close() throws IOException {
        digest = mac.doFinal();
    }

    public byte[] getMac() {
        return digest;
    }
}
