package com.exploids.filecrypt.utility;

import java.io.IOException;
import java.security.Signature;
import java.security.SignatureException;

/**
 * An output stream that feeds all bytes to a signature.
 *
 * @author Luca Selinski
 */
public class SignatureOutputStream extends ConsumingOutputStream<Signature> {
    /**
     * The signature calculation.
     */
    private final Signature signature;

    /**
     * Creates a new signature output stream.
     *
     * @param signature the signature
     */
    public SignatureOutputStream(Signature signature) {
        this.signature = signature;
    }

    /**
     * Updates the signature.
     *
     * @param b the byte
     */
    @Override
    public void write(int b) throws IOException {
        try {
            signature.update((byte) b);
        } catch (SignatureException e) {
            throw new IOException("signature update failed", e);
        }
    }

    /**
     * Updates the signature.
     *
     * @param b the data
     */
    @SuppressWarnings("NullableProblems")
    @Override
    public void write(byte[] b) throws IOException {
        try {
            signature.update(b);
        } catch (SignatureException e) {
            throw new IOException("signature update failed", e);
        }
    }

    /**
     * Updates the signature.
     *
     * @param b   the data
     * @param off the start offset in the data
     * @param len the number of bytes to write
     */
    @SuppressWarnings("NullableProblems")
    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        try {
            signature.update(b, off, len);
        } catch (SignatureException e) {
            throw new IOException("signature update failed", e);
        }
    }

    /**
     * Gets the signature calculation
     *
     * @return the signature
     */
    @Override
    public Signature getResult() {
        return signature;
    }
}
