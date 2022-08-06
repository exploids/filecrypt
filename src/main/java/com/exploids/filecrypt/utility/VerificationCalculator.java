package com.exploids.filecrypt.utility;

import java.io.OutputStream;

/**
 * @author Luca Selinski
 */
public abstract class VerificationCalculator extends OutputStream {
    public abstract byte[] getEncoded();
}
