package com.exploids.filecrypt.exception;

/**
 * An exception that indicates a failed verification of a MAC/hash.
 *
 * @author Luca Selinski
 */
public class VerificationFailedException extends FileCryptException {
    /**
     * The expected MAC/hash.
     */
    private final byte[] expected;

    /**
     * The actual MAC/hash.
     */
    private final byte[] actual;

    /**
     * Instantiates a new exception.
     *
     * @param expected the expected MAC/hash
     * @param actual   the actual MAC/hash
     */
    public VerificationFailedException(byte[] expected, byte[] actual) {
        super("The verification of the MAC/hash failed");
        this.expected = expected;
        this.actual = actual;
    }

    /**
     * Gets the expected value of this verification failed exception.
     *
     * @return the expected value
     */
    public byte[] getExpected() {
        return expected;
    }

    /**
     * Gets the actual value of this verification failed exception.
     *
     * @return the actual value
     */
    public byte[] getActual() {
        return actual;
    }
}
