package com.exploids.filecrypt.step;

import com.exploids.filecrypt.action.Action;
import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Parameters;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * A single step during encryption/decryption.
 *
 * @author Luca Selinski
 */
public interface Step {
    /**
     * Checks whether the step is used with the given metadata.
     *
     * @param metadata the metadata
     * @return true if the step is used
     */
    boolean applies(Metadata metadata);

    /**
     * Builds an action to execute this step.
     *
     * @param parameters the command line parameters
     * @param metadata   the metadata
     * @param cipher     the cipher to use
     * @param cipherKey  the key to use
     * @param decode     whether the action is used to decode a file
     * @return the action
     */
    Action buildAction(Parameters parameters, Metadata metadata, Cipher cipher, SecretKey cipherKey, boolean decode);
}
