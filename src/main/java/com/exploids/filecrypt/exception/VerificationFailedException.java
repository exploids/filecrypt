package com.exploids.filecrypt.exception;

/**
 * @author Luca Selinski
 */
public class VerificationFailedException extends FileCryptException {
    private final byte[] expected;
    private final byte[] actual;

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
