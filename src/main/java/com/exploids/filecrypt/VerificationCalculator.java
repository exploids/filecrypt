package com.exploids.filecrypt;

import java.io.OutputStream;

/**
 * @author Luca Selinski
 */
public abstract class VerificationCalculator extends OutputStream {
    public abstract byte[] getEncoded();
}
