package com.exploids.filecrypt;

import picocli.CommandLine;

import java.nio.ByteBuffer;

public class KeyData {
    @CommandLine.Option(names = {"--cipher-key"})
    private ByteBuffer cipherKey;

    @CommandLine.Option(names = {"--mac-key"})
    private ByteBuffer macKey;

    public ByteBuffer getCipherKey() {
        return cipherKey;
    }

    public void setCipherKey(ByteBuffer cipherKey) {
        this.cipherKey = cipherKey;
    }

    public ByteBuffer getMacKey() {
        return macKey;
    }

    public void setMacKey(ByteBuffer macKey) {
        this.macKey = macKey;
    }
}
