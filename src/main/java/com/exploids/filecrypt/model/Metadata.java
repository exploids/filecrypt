package com.exploids.filecrypt.model;

import com.exploids.filecrypt.serialization.ByteBufferDeserializer;
import com.exploids.filecrypt.serialization.ByteBufferSerializer;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import picocli.CommandLine.Option;

import java.nio.ByteBuffer;

/**
 * Metadata that describes a concrete cipher.
 *
 * @author Luca Selinski
 */
public class Metadata {
    /**
     * Creates new empty metadata.
     */
    public Metadata() {
    }

    /**
     * Creates metadata from the given values.
     *
     * @param cipherAlgorithm            the algorithm
     * @param blockMode            the block mode
     * @param padding              the padding
     * @param initializationVector the iv
     */
    public Metadata(Algorithm cipherAlgorithm, BlockMode blockMode, Padding padding, ByteBuffer initializationVector) {
        this.cipherAlgorithm = cipherAlgorithm;
        this.blockMode = blockMode;
        this.padding = padding;
        this.initializationVector = initializationVector;
    }

    /**
     * The algorithm.
     */
    @Option(names = {"--algorithm"})
    private Algorithm cipherAlgorithm;

    /**
     * The block mode.
     */
    @Option(names = {"--block-mode"})
    private BlockMode blockMode;

    /**
     * The padding.
     */
    @Option(names = {"--padding"})
    private Padding padding;

    /**
     * The padding.
     */
    @Option(names = {"--key-size"})
    private int keySize;

    /**
     * The initialization vector.
     */
    @Option(names = {"--iv"})
    private ByteBuffer initializationVector;

    /**
     * The MAC algorithm.
     */
    @Option(names = {"--mac-algorithm"})
    private MacAlgorithm macAlgorithm;

    /**
     * The MAC.
     */
    @Option(names = {"-m", "--mac"}, arity = "0..1")
    private ByteBuffer mac;

    /**
     * Gets the algorithm of this metadata.
     *
     * @return the algorithm
     */
    public Algorithm getCipherAlgorithm() {
        return cipherAlgorithm;
    }

    /**
     * Sets the algorithm of this metadata.
     *
     * @param cipherAlgorithm the new algorithm
     */
    public void setCipherAlgorithm(Algorithm cipherAlgorithm) {
        this.cipherAlgorithm = cipherAlgorithm;
    }

    /**
     * Gets the block mode of this metadata.
     *
     * @return the block mode
     */
    public BlockMode getBlockMode() {
        return blockMode;
    }

    /**
     * Sets the blockMode of this metadata.
     *
     * @param blockMode the new blockMode
     */
    public void setBlockMode(BlockMode blockMode) {
        this.blockMode = blockMode;
    }

    /**
     * Gets the padding of this metadata.
     *
     * @return the padding
     */
    public Padding getPadding() {
        return padding;
    }

    /**
     * Sets the padding of this metadata.
     *
     * @param padding the new padding
     */
    public void setPadding(Padding padding) {
        this.padding = padding;
    }

    /**
     * Gets the key size of this metadata.
     *
     * @return the key size
     */
    public int getKeySize() {
        return keySize;
    }

    /**
     * Sets the key size if this metadata.
     *
     * @param keySize the new key size
     */
    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }

    /**
     * Gets the mac algorithm of this metadata.
     *
     * @return the mac algorithm
     */
    public MacAlgorithm getMacAlgorithm() {
        return macAlgorithm;
    }

    /**
     * Sets the macAlgorithm of this metadata.
     *
     * @param macAlgorithm the new macAlgorithm
     */
    public void setMacAlgorithm(MacAlgorithm macAlgorithm) {
        this.macAlgorithm = macAlgorithm;
    }

    /**
     * Gets the mac of this metadata.
     *
     * @return the mac
     */
    @JsonSerialize(using = ByteBufferSerializer.class)
    public ByteBuffer getMac() {
        return mac;
    }

    /**
     * Sets the mac of this metadata.
     *
     * @param mac the new mac
     */
    @JsonDeserialize(using = ByteBufferDeserializer.class)
    public void setMac(ByteBuffer mac) {
        this.mac = mac;
    }

    /**
     * Gets the initialization vector of this metadata.
     *
     * @return the initialization vector
     */
    @JsonSerialize(using = ByteBufferSerializer.class)
    public ByteBuffer getInitializationVector() {
        return initializationVector;
    }

    /**
     * Sets the initialization vector of this metadata.
     *
     * @param initializationVector the new initialization vector
     */
    @JsonDeserialize(using = ByteBufferDeserializer.class)
    public void setInitializationVector(ByteBuffer initializationVector) {
        this.initializationVector = initializationVector;
    }

    /**
     * Sets all non-null values from the other metadata.
     *
     * @param other the metadata to read from
     */
    public void setFrom(Metadata other) {
        if (other.cipherAlgorithm != null) {
            cipherAlgorithm = other.cipherAlgorithm;
        }
        if (other.blockMode != null) {
            blockMode = other.blockMode;
        }
        if (other.padding != null) {
            padding = other.padding;
        }
        if (other.keySize != 0) {
            keySize = other.keySize;
        }
        if (other.initializationVector != null) {
            initializationVector = other.initializationVector;
        }
        if (other.macAlgorithm != null) {
            macAlgorithm = other.macAlgorithm;
        }
        if (other.mac != null) {
            mac = other.mac;
        }
    }

    @Override
    public String toString() {
        return "Metadata{" +
                "algorithm=" + cipherAlgorithm +
                ", blockMode=" + blockMode +
                ", padding=" + padding +
                ", keySize=" + keySize +
                ", initializationVector=" + initializationVector +
                ", macAlgorithm=" + macAlgorithm +
                ", mac=" + mac +
                '}';
    }
}
