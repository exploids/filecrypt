package com.exploids.filecrypt.utility;

import javax.crypto.Mac;

/**
 * @author Luca Selinski
 */
public class MacOutputStream extends ConsumingOutputStream<byte[]> {
    private final Mac mac;
    private byte[] digest;

    public MacOutputStream(Mac mac) {
        this.mac = mac;
    }

    @Override
    public void write(int b) {
        mac.update((byte) b);
    }

    @Override
    public void write(byte[] b) {
        mac.update(b);
    }

    @Override
    public void write(byte[] b, int off, int len) {
        mac.update(b, off, len);
    }

    @Override
    public void close() {
        digest = mac.doFinal();
    }

    @Override
    public byte[] getResult() {
        return digest;
    }
}
