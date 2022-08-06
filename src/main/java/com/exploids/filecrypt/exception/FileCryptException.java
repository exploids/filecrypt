package com.exploids.filecrypt.exception;

/**
 * The super class for all exceptions specifix to filecrypt.
 *
 * @author Luca Selinski
 */
public class FileCryptException extends Exception {
    /**
     * Instantiates a new filecrypt exception.
     */
    public FileCryptException() {
        super();
    }

    /**
     * Instantiates a new filecrypt exception.
     *
     * @param message the detail message
     */
    public FileCryptException(String message) {
        super(message);
    }
}
