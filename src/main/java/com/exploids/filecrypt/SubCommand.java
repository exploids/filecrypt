package com.exploids.filecrypt;

import com.exploids.filecrypt.exception.FileCryptException;
import com.exploids.filecrypt.exception.InsecureException;
import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Parameters;
import com.exploids.filecrypt.utility.FileCleanup;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

public interface SubCommand {
    String outputBaseName(String baseName);
    String companionBaseName(String baseName);
    void init(Parameters parameters, Metadata combinedMetadata, Cipher cipher, FileCleanup cleanup);
    void check() throws InsecureException;
    OutputStream call(SecretKey cipherKey, OutputStream out) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, FileCryptException, InvalidKeySpecException;
    void doFinal() throws FileCryptException, IOException, SignatureException;
}
