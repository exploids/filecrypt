package com.exploids.filecrypt;

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
     * @param algorithm            the algorithm
     * @param blockMode            the block mode
     * @param padding              the padding
     * @param initializationVector the iv
     */
    public Metadata(Algorithm algorithm, BlockMode blockMode, Padding padding, ByteBuffer initializationVector) {
        this.algorithm = algorithm;
        this.blockMode = blockMode;
        this.padding = padding;
        this.initializationVector = initializationVector;
    }

    /**
     * The algorithm.
     */
    @Option(names = {"-a", "--algorithm"})
    private Algorithm algorithm;

    /**
     * The block mode.
     */
    @Option(names = {"-b", "--block-mode"})
    private BlockMode blockMode;

    /**
     * The padding.
     */
    @Option(names = {"-d", "--padding"})
    private Padding padding;

    /**
     * The padding.
     */
    @Option(names = {"--key-size"})
    private int keySize;

    /**
     * The initialization vector.
     */
    @Option(names = {"--iv", "--initialization-vector"})
    private ByteBuffer initializationVector;

    /**
     * Gets the algorithm of this metadata.
     *
     * @return the algorithm
     */
    public Algorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * Sets the algorithm of this metadata.
     *
     * @param algorithm the new algorithm
     */
    public void setAlgorithm(Algorithm algorithm) {
        this.algorithm = algorithm;
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
     * Gets the initialization vector of this metadata.
     *
     * @return the initialization vector
     */
    @JsonSerialize(using = ByteArraySerializer.class)
    public byte[] getInitializationVector() {
        return initializationVector == null ? null : initializationVector.array();
    }

    /**
     * Sets the initialization vector of this metadata.
     *
     * @param initializationVector the new initialization vector
     */
    @JsonDeserialize(using = ByteArrayDeserializer.class)
    public void setInitializationVector(byte[] initializationVector) {
        this.initializationVector = ByteBuffer.wrap(initializationVector);
    }

    /**
     * Sets all non-null values from the other metadata.
     *
     * @param other the metadata to read from
     */
    public void setFrom(Metadata other) {
        if (other.algorithm != null) {
            algorithm = other.algorithm;
        }
        if (other.blockMode != null) {
            blockMode = other.blockMode;
        }
        if (other.padding != null) {
            padding = other.padding;
        }
        if (other.initializationVector != null) {
            initializationVector = other.initializationVector;
        }
    }

    @Override
    public String toString() {
        return "Metadata{" +
                "algorithm=" + algorithm +
                ", blockMode=" + blockMode +
                ", padding=" + padding +
                ", initializationVector=" + initializationVector +
                '}';
    }
}
