package com.exploids.filecrypt.step;

import com.exploids.filecrypt.action.Action;
import com.exploids.filecrypt.action.BasicAction;
import com.exploids.filecrypt.action.SaveDataAction;
import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Parameters;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * A step that saves data.
 *
 * @author Luca Selinski
 */
public class SaveDataStep implements Step {
    @Override
    public boolean applies(Metadata metadata) {
        return true;
    }

    @Override
    public Action buildAction(Parameters parameters, Metadata metadata, Cipher cipher, SecretKey cipherKey, boolean decode) {
        if (decode) {
            return new BasicAction(parameters, metadata, cipher, cipherKey);
        } else {
            return new SaveDataAction(parameters, metadata, cipher, cipherKey);
        }
    }
}
