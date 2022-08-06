package com.exploids.filecrypt;

import com.exploids.filecrypt.exception.InsecureException;
import com.exploids.filecrypt.model.BlockMode;
import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Padding;

import java.util.EnumSet;
import java.util.Set;

/**
 * Checks algorithm parameters for security issues.
 *
 * @author Luca Selinski
 */
public class SecurityCheck {
    /**
     * Checks the given parameters.
     *
     * @param metadata the parameters to check
     * @return a set of all security concerns
     */
    public Set<Concern> check(Metadata metadata) {
        var concerns = EnumSet.noneOf(Concern.class);
//        if (metadata.getCipherAlgorithm() != Algorithm.AES) {
//            concerns.add(Concern.ALGORITHM);
//        }
        if (metadata.getBlockMode() == BlockMode.ECB) {
            concerns.add(Concern.BLOCK_MODE);
        }
        if (metadata.getPadding() == Padding.ZERO_BYTE) {
            concerns.add(Concern.PADDING);
        }
        return concerns;
    }

    /**
     * Checks the given parameters.
     *
     * @param metadata the parameters to check
     * @throws InsecureException if there are security concerns
     */
    public void checkAndThrow(Metadata metadata) throws InsecureException {
        var concerns = check(metadata);
        if (!concerns.isEmpty()) {
            throw new InsecureException(concerns);
        }
    }

    /**
     * A security concern.
     */
    public enum Concern {
        /**
         * The selected algorithm raises concerns.
         */
        ALGORITHM,

        /**
         * The selected block mode raises concerns.
         */
        BLOCK_MODE,

        /**
         * The selected padding raises concerns.
         */
        PADDING,
    }
}
