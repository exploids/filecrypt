package com.exploids.filecrypt.model;

import com.exploids.filecrypt.serialization.Base64ByteBufferConverter;
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
    private Integer keySize;

    /**
     * The initialization vector.
     */
    @Option(names = {"--iv"})
    private ByteBuffer initializationVector;

    /**
     * The algorithm for the password.
     */
    @Option(names = {"--password-algorithm"})
    private PasswordAlgorithm passwordAlgorithm;

    /**
     * The salt for the password.
     */
    @Option(names = {"--password-salt"})
    private ByteBuffer passwordSalt;

    /**
     * The cost parameter for the password.
     */
    @Option(names = {"--password-cost"})
    private Integer passwordCost;

    /**
     * The block size for the password.
     */
    @Option(names = {"--password-block-size"})
    private Integer passwordBlockSize;

    /**
     * The parallelization parameter for the password.
     */
    @Option(names = {"--password-parallelization"})
    private Integer passwordParallelization;

    /**
     * The MAC/hash algorithm.
     */
    @Option(names = {"--verification-algorithm"})
    private VerificationAlgorithm verificationAlgorithm;

    /**
     * The MAC/hash.
     */
    @Option(names = {"-v", "--verification"}, arity = "0..1")
    private ByteBuffer verification;

    /**
     * The signature.
     */
    @Option(names = {"--signature"}, arity = "0..1", converter = Base64ByteBufferConverter.class)
    private ByteBuffer signature;

    /**
     * The signature.
     */
    @Option(names = {"--signature-public-key"}, converter = Base64ByteBufferConverter.class)
    private ByteBuffer signaturePublicKey;

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
    public Integer getKeySize() {
        return keySize;
    }

    /**
     * Sets the key size if this metadata.
     *
     * @param keySize the new key size
     */
    public void setKeySize(Integer keySize) {
        this.keySize = keySize;
    }

    public PasswordAlgorithm getPasswordAlgorithm() {
        return passwordAlgorithm;
    }

    public void setPasswordAlgorithm(PasswordAlgorithm passwordAlgorithm) {
        this.passwordAlgorithm = passwordAlgorithm;
    }

    @JsonSerialize(using = ByteBufferSerializer.class)
    public ByteBuffer getPasswordSalt() {
        return passwordSalt;
    }

    @JsonDeserialize(using = ByteBufferDeserializer.class)
    public void setPasswordSalt(ByteBuffer passwordSalt) {
        this.passwordSalt = passwordSalt;
    }

    public Integer getPasswordCost() {
        return passwordCost;
    }

    public void setPasswordCost(Integer passwordCost) {
        this.passwordCost = passwordCost;
    }

    public Integer getPasswordBlockSize() {
        return passwordBlockSize;
    }

    public void setPasswordBlockSize(Integer passwordBlockSize) {
        this.passwordBlockSize = passwordBlockSize;
    }

    public Integer getPasswordParallelization() {
        return passwordParallelization;
    }

    public void setPasswordParallelization(Integer passwordParallelization) {
        this.passwordParallelization = passwordParallelization;
    }

    /**
     * Gets the mac algorithm of this metadata.
     *
     * @return the mac algorithm
     */
    public VerificationAlgorithm getVerificationAlgorithm() {
        return verificationAlgorithm;
    }

    /**
     * Sets the verificationAlgorithm of this metadata.
     *
     * @param verificationAlgorithm the new verificationAlgorithm
     */
    public void setVerificationAlgorithm(VerificationAlgorithm verificationAlgorithm) {
        this.verificationAlgorithm = verificationAlgorithm;
    }

    /**
     * Gets the mac of this metadata.
     *
     * @return the mac
     */
    @JsonSerialize(using = ByteBufferSerializer.class)
    public ByteBuffer getVerification() {
        return verification;
    }

    /**
     * Sets the mac of this metadata.
     *
     * @param verification the new mac
     */
    @JsonDeserialize(using = ByteBufferDeserializer.class)
    public void setVerification(ByteBuffer verification) {
        this.verification = verification;
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
     * Gets the signature of this metadata.
     *
     * @return the signature
     */
    public ByteBuffer getSignature() {
        return signature;
    }

    /**
     * Sets the signature of this metadata.
     *
     * @param signature the new signature
     */
    public void setSignature(ByteBuffer signature) {
        this.signature = signature;
    }

    /**
     * Gets the signaturePublicKey of this metadata.
     *
     * @return the signaturePublicKey
     */

    public ByteBuffer getSignaturePublicKey() {
        return signaturePublicKey;
    }

    /**
     * Sets the signaturePublicKey of this metadata.
     *
     * @param signaturePublicKey the new signaturePublicKey
     */

    public void setSignaturePublicKey(ByteBuffer signaturePublicKey) {
        this.signaturePublicKey = signaturePublicKey;
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
        if (other.keySize != null) {
            keySize = other.keySize;
        }
        if (other.initializationVector != null) {
            initializationVector = other.initializationVector;
        }
        if (other.passwordAlgorithm != null) {
            passwordAlgorithm = other.passwordAlgorithm;
        }
        if (other.passwordSalt != null) {
            passwordSalt = other.passwordSalt;
        }
        if (other.passwordCost != null) {
            passwordCost = other.passwordCost;
        }
        if (other.passwordBlockSize != null) {
            passwordBlockSize = other.passwordBlockSize;
        }
        if (other.passwordParallelization != null) {
            passwordParallelization = other.passwordParallelization;
        }
        if (other.verificationAlgorithm != null) {
            verificationAlgorithm = other.verificationAlgorithm;
        }
        if (other.verification != null) {
            verification = other.verification;
        }
        if (other.signature != null) {
            signature = other.signature;
        }
        if (other.signaturePublicKey != null) {
            signaturePublicKey = other.signaturePublicKey;
        }
    }

    @Override
    public String toString() {
        return "Metadata{" +
                "cipherAlgorithm=" + cipherAlgorithm +
                ", blockMode=" + blockMode +
                ", padding=" + padding +
                ", keySize=" + keySize +
                ", initializationVector=" + initializationVector +
                ", passwordAlgorithm=" + passwordAlgorithm +
                ", passwordSalt=" + passwordSalt +
                ", passwordCost=" + passwordCost +
                ", passwordBlockSize=" + passwordBlockSize +
                ", passwordParallelization=" + passwordParallelization +
                ", verificationAlgorithm=" + verificationAlgorithm +
                ", verification=" + verification +
                ", signature=" + signature +
                ", signaturePublicKey=" + signaturePublicKey +
                '}';
    }
}
