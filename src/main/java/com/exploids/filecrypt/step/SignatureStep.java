package com.exploids.filecrypt.step;

import com.exploids.filecrypt.action.Action;
import com.exploids.filecrypt.action.SignatureSignAction;
import com.exploids.filecrypt.action.SignatureVerifyAction;
import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Parameters;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * A signature step.
 *
 * @author Luca Selinski
 */
public class SignatureStep implements Step {
    @Override
    public boolean applies(Metadata metadata) {
        return metadata.getSignature() != null;
    }

    @Override
    public Action buildAction(Parameters parameters, Metadata metadata, Cipher cipher, SecretKey cipherKey, boolean decode) {
        if (decode) {
            return new SignatureVerifyAction(parameters, metadata, cipher, cipherKey);
        } else {
            return new SignatureSignAction(parameters, metadata, cipher, cipherKey);
        }
    }
}
