package com.exploids.filecrypt.action;

import com.exploids.filecrypt.exception.InsecureException;
import com.exploids.filecrypt.exception.InvalidSignatureException;
import com.exploids.filecrypt.exception.MissingMacKeyException;
import com.exploids.filecrypt.exception.VerificationFailedException;
import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Parameters;
import com.exploids.filecrypt.utility.FileCleanup;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.SignatureException;

/**
 * A base implementation for actions.
 *
 * @author Luca Selinski
 */
public class BasicAction implements Action {
    /**
     * The command line parameters.
     */
    final Parameters parameters;

    /**
     * The metadata.
     */
    final Metadata metadata;

    /**
     * The cipher to use.
     */

    final Cipher cipher;

    /**
     * The key to use.
     */
    final SecretKey cipherKey;

    /**
     * Creates a new basic action.
     *
     * @param parameters the command line parameters
     * @param metadata   the metadata
     * @param cipher     the cipher to use
     * @param cipherKey  the key to use
     */
    public BasicAction(Parameters parameters, Metadata metadata, Cipher cipher, SecretKey cipherKey) {
        this.parameters = parameters;
        this.metadata = metadata;
        this.cipher = cipher;
        this.cipherKey = cipherKey;
    }

    @Override
    public void begin() throws InsecureException {
    }

    @Override
    public OutputStream call(OutputStream stream) throws MissingMacKeyException, GeneralSecurityException {
        return stream;
    }

    @Override
    public void end(ObjectMapper mapper, FileCleanup cleanup) throws VerificationFailedException, SignatureException, InvalidSignatureException, IOException {
    }
}
