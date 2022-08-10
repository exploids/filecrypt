package com.exploids.filecrypt.utility;

import java.io.OutputStream;

/**
 * An output stream that consumes bytes, producing a single result.
 *
 * @param <T> the type of the result
 * @author Luca Selinski
 */
public abstract class ConsumingOutputStream<T> extends OutputStream {
    /**
     * Gets the result.
     *
     * @return the result
     */
    public abstract T getResult();
}
