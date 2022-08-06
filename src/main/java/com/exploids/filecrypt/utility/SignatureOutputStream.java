package com.exploids.filecrypt.utility;

import java.io.IOException;
import java.security.Signature;
import java.security.SignatureException;

/**
 * @author Luca Selinski
 */
public class SignatureOutputStream extends ConsumingOutputStream<Signature> {
    private final Signature signature;

    public SignatureOutputStream(Signature signature) {
        this.signature = signature;
    }

    @Override
    public void write(int b) throws IOException {
        try {
            signature.update((byte) b);
        } catch (SignatureException e) {
            throw new IOException("signature update failed", e);
        }
    }

    @Override
    public void write(byte[] b) throws IOException {
        try {
            signature.update(b);
        } catch (SignatureException e) {
            throw new IOException("signature update failed", e);
        }
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        try {
            signature.update(b, off, len);
        } catch (SignatureException e) {
            throw new IOException("signature update failed", e);
        }
    }

    @Override
    public Signature getResult() {
        return signature;
    }
}
