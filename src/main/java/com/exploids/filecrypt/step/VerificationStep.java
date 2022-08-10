package com.exploids.filecrypt.step;

import com.exploids.filecrypt.action.Action;
import com.exploids.filecrypt.action.VerificationCheckAction;
import com.exploids.filecrypt.action.VerificationGenerationAction;
import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Parameters;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * A MAC/hash verification step.
 *
 * @author Luca Selinski
 */
public class VerificationStep implements Step {
    @Override
    public boolean applies(Metadata metadata) {
        return metadata.getVerification() != null;
    }

    @Override
    public Action buildAction(Parameters parameters, Metadata metadata, Cipher cipher, SecretKey cipherKey, boolean decode) {
        if (decode) {
            return new VerificationCheckAction(parameters, metadata, cipher, cipherKey);
        } else {
            return new VerificationGenerationAction(parameters, metadata, cipher, cipherKey);
        }
    }
}
