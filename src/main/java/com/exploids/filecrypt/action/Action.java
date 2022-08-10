package com.exploids.filecrypt.action;

import com.exploids.filecrypt.exception.FileCryptException;
import com.exploids.filecrypt.exception.InsecureException;
import com.exploids.filecrypt.utility.FileCleanup;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

/**
 * A single action to perform on a file.
 *
 * @author Luca Selinski
 */
public interface Action {
    /**
     * Called before the file is processed.
     *
     * @throws InsecureException if some parameters are insecure
     */
    void begin() throws InsecureException;

    /**
     * Called when the file is being processed.
     *
     * @param stream the target stream
     * @return the source stream
     * @throws FileCryptException       if a filecrypt specific exception occurs
     * @throws GeneralSecurityException if some security parameters cause issues
     */
    OutputStream call(OutputStream stream) throws FileCryptException, GeneralSecurityException;

    /**
     * Called after the file has been processed.
     *
     * @param mapper  the serializer for objects
     * @param cleanup the file clean up manager
     * @throws FileCryptException       if a filecrypt specific exception occurs
     * @throws GeneralSecurityException if some security parameters cause issues
     * @throws IOException              if an I/O error occurs
     */
    void end(ObjectMapper mapper, FileCleanup cleanup) throws FileCryptException, GeneralSecurityException, IOException;
}
