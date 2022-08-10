package com.exploids.filecrypt.action;

import com.exploids.filecrypt.exception.InvalidSignatureException;
import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Parameters;
import com.exploids.filecrypt.utility.FileCleanup;
import com.exploids.filecrypt.utility.SignatureOutputStream;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.output.TeeOutputStream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;

/**
 * Verifies file signatures.
 *
 * @author Luca Selinski
 */
public class SignatureVerifyAction extends BasicAction {
    /**
     * The signature.
     */
    private Signature signature;

    /**
     * Creates a new verify action.
     *
     * @param parameters the command line parameters
     * @param metadata   the metadata
     * @param cipher     the cipher to use
     * @param cipherKey  the key to use
     */
    public SignatureVerifyAction(Parameters parameters, Metadata metadata, Cipher cipher, SecretKey cipherKey) {
        super(parameters, metadata, cipher, cipherKey);
    }

    @Override
    public OutputStream call(OutputStream stream) throws GeneralSecurityException {
        var keyFact = KeyFactory.getInstance("DSA", "BC");
        var publicKey = keyFact.generatePublic(new X509EncodedKeySpec(metadata.getSignaturePublicKey().array()));
        signature = Signature.getInstance("SHA256withDSA", "BC");
        signature.initVerify(publicKey);
        return new TeeOutputStream(stream, new SignatureOutputStream(signature));
    }

    @Override
    public void end(ObjectMapper mapper, FileCleanup cleanup) throws SignatureException, InvalidSignatureException {
        if (!signature.verify(metadata.getSignature().array())) {
            throw new InvalidSignatureException();
        }
    }
}
