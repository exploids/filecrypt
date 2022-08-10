package com.exploids.filecrypt.action;

import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Parameters;
import com.exploids.filecrypt.utility.FileCleanup;
import com.exploids.filecrypt.utility.SignatureOutputStream;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.output.TeeOutputStream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Signs files.
 *
 * @author Luca Selinski
 */
public class SignatureSignAction extends BasicAction {
    /**
     * The signature.
     */
    private Signature signature;

    /**
     * Creates a new sign action.
     *
     * @param parameters the command line parameters
     * @param metadata   the metadata
     * @param cipher     the cipher to use
     * @param cipherKey  the key to use
     */
    public SignatureSignAction(Parameters parameters, Metadata metadata, Cipher cipher, SecretKey cipherKey) {
        super(parameters, metadata, cipher, cipherKey);
    }

    @Override
    public OutputStream call(OutputStream stream) throws GeneralSecurityException {
        var encodedPrivateKey = parameters.getSignaturePrivateKey();
        PrivateKey privateKey;
        if (encodedPrivateKey == null) {
            var generator = KeyPairGenerator.getInstance("DSA", "BC");
            generator.initialize(3072);
            var keyPair = generator.generateKeyPair();
            privateKey = keyPair.getPrivate();
            metadata.setSignaturePublicKey(ByteBuffer.wrap(keyPair.getPublic().getEncoded()));
            parameters.setSignaturePrivateKey(ByteBuffer.wrap(privateKey.getEncoded()));
        } else {
            var keyFact = KeyFactory.getInstance("DSA", "BC");
            privateKey = keyFact.generatePrivate(new PKCS8EncodedKeySpec(encodedPrivateKey.array()));
        }
        signature = Signature.getInstance("SHA256withDSA", "BC");
        signature.initSign(privateKey);
        return new TeeOutputStream(stream, new SignatureOutputStream(signature));
    }

    @Override
    public void end(ObjectMapper mapper, FileCleanup cleanup) throws SignatureException {
        metadata.setSignature(ByteBuffer.wrap(signature.sign()));
    }
}
