package com.exploids.filecrypt;

import java.util.Arrays;

/**
 * @author Luca Selinski
 */
public class Metadata {
    /**
     * The algorithm.
     */
    private Algorithm algorithm;

    /**
     * The block mode.
     */
    private BlockMode blockMode;

    /**
     * The padding.
     */
    private Padding padding;

    /**
     * The initialization vector.
     */
    private byte[] initializationVector;

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
     * Gets the initialization vector of this metadata.
     *
     * @return the initialization vector
     */
    public byte[] getInitializationVector() {
        return initializationVector;
    }

    /**
     * Sets the initialization vector of this metadata.
     *
     * @param initializationVector the new initialization vector
     */
    public void setInitializationVector(byte[] initializationVector) {
        this.initializationVector = initializationVector;
    }

    @Override
    public String toString() {
        return "Metadata{" +
                "algorithm=" + algorithm +
                ", blockMode=" + blockMode +
                ", padding=" + padding +
                ", initializationVector=" + Arrays.toString(initializationVector) +
                '}';
    }
}
