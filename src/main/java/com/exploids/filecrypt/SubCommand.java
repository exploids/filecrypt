package com.exploids.filecrypt;

import com.exploids.filecrypt.exception.FileCryptException;
import com.exploids.filecrypt.exception.InsecureException;
import com.exploids.filecrypt.exception.VerificationFailedException;
import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Parameters;
import org.bouncycastle.cms.CMSException;

import javax.crypto.Cipher;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public interface SubCommand {
    String outputBaseName(String baseName);
    String companionBaseName(String baseName);
    void init(Parameters parameters, Metadata combinedMetadata, Cipher cipher);
    void check() throws InsecureException;
    OutputStream call(OutputStream out) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, VerificationFailedException;
    void doFinal() throws FileCryptException, IOException;
}
