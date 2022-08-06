package com.exploids.filecrypt.exception;

import com.exploids.filecrypt.SecurityCheck;

import java.util.Set;

/**
 * An exception that is thrown if there are security concerns.
 *
 * @author Luca Selinski
 */
public class InsecureException extends FileCryptException {
    /**
     * The concrete concerns.
     */
    private final Set<SecurityCheck.Concern> concerns;

    /**
     * Creates a new insecure exception.
     *
     * @param concerns the concrete concerns
     */
    public InsecureException(Set<SecurityCheck.Concern> concerns) {
        super(concerns.toString());
        this.concerns = concerns;
    }

    /**
     * Gets the concerns of this insecure exception.
     *
     * @return the concerns
     */
    public Set<SecurityCheck.Concern> getConcerns() {
        return concerns;
    }
}
