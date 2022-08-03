package com.exploids.filecrypt;

import com.exploids.filecrypt.exception.FileCryptException;
import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Parameters;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;

import javax.crypto.Cipher;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public interface SubCommand {
    String outputBaseName(String baseName);
    String companionBaseName(String baseName);
    void call(Parameters parameters, Metadata combinedMetadata, Cipher cipher, InputStream in, OutputStream out) throws FileCryptException, IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, InvalidAlgorithmParameterException, CMSException;
}
