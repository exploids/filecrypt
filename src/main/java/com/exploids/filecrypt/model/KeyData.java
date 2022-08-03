package com.exploids.filecrypt.model;

import com.exploids.filecrypt.serialization.ByteBufferDeserializer;
import com.exploids.filecrypt.serialization.ByteBufferSerializer;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import picocli.CommandLine;

import java.nio.ByteBuffer;

public class KeyData {
    @CommandLine.Option(names = {"--cipher-key"})
    private ByteBuffer cipherKey;

    @CommandLine.Option(names = {"--mac-key"})
    private ByteBuffer macKey;

    @JsonSerialize(using = ByteBufferSerializer.class)
    public ByteBuffer getCipherKey() {
        return cipherKey;
    }

    @JsonDeserialize(using = ByteBufferDeserializer.class)
    public void setCipherKey(ByteBuffer cipherKey) {
        this.cipherKey = cipherKey;
    }

    @JsonSerialize(using = ByteBufferSerializer.class)
    public ByteBuffer getMacKey() {
        return macKey;
    }

    @JsonDeserialize(using = ByteBufferDeserializer.class)
    public void setMacKey(ByteBuffer macKey) {
        this.macKey = macKey;
    }
}
