package com.exploids.filecrypt.model;

import com.exploids.filecrypt.serialization.ByteBufferDeserializer;
import com.exploids.filecrypt.serialization.ByteBufferSerializer;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import picocli.CommandLine;

import java.nio.ByteBuffer;

/**
 * The model for private keys shared with the recipient.
 *
 * @author Luca Selinski
 */
public class KeyData {
    /**
     * The key for decryption.
     */
    @CommandLine.Option(names = {"--cipher-key"})
    private ByteBuffer cipherKey;

    /**
     * The key for the MAC.
     */
    @CommandLine.Option(names = {"--verification-key"})
    private ByteBuffer verificationKey;

    /**
     * Gets the key for decryption.
     *
     * @return the key for decryption
     */
    @JsonSerialize(using = ByteBufferSerializer.class)
    public ByteBuffer getCipherKey() {
        return cipherKey;
    }

    /**
     * Sets the key for decryption.
     *
     * @param cipherKey the key for decryption
     */
    @JsonDeserialize(using = ByteBufferDeserializer.class)
    public void setCipherKey(ByteBuffer cipherKey) {
        this.cipherKey = cipherKey;
    }

    /**
     * Gets the key for the MAC.
     *
     * @return the key for the MAC
     */
    @JsonSerialize(using = ByteBufferSerializer.class)
    public ByteBuffer getVerificationKey() {
        return verificationKey;
    }

    /**
     * Sets the key for the MAC.
     *
     * @param verificationKey the key for the MAC
     */
    @JsonDeserialize(using = ByteBufferDeserializer.class)
    public void setVerificationKey(ByteBuffer verificationKey) {
        this.verificationKey = verificationKey;
    }
}
