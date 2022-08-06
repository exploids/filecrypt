package com.exploids.filecrypt.utility;

import java.io.OutputStream;

/**
 * @author Luca Selinski
 */
public abstract class ConsumingOutputStream<T> extends OutputStream {
    public abstract T getResult();
}
