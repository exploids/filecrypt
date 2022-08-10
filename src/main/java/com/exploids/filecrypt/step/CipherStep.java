package com.exploids.filecrypt.step;

import com.exploids.filecrypt.action.Action;
import com.exploids.filecrypt.action.CipherDecryptAction;
import com.exploids.filecrypt.action.CipherEncryptAction;
import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Parameters;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * An encryption/decryption step.
 *
 * @author Luca Selinski
 */
public class CipherStep implements Step {
    @Override
    public boolean applies(Metadata metadata) {
        return true;
    }

    @Override
    public Action buildAction(Parameters parameters, Metadata metadata, Cipher cipher, SecretKey cipherKey, boolean decode) {
        if (decode) {
            return new CipherDecryptAction(parameters, metadata, cipher, cipherKey);
        } else {
            return new CipherEncryptAction(parameters, metadata, cipher, cipherKey);
        }
    }
}
