package com.exploids.filecrypt;

import com.exploids.filecrypt.exception.MacVerificationFailedException;
import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Parameters;
import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.TeeInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class DecryptionCommand implements SubCommand {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Override
    public String outputBaseName(String baseName) {
        return baseName + "_decrypted";
    }

    @Override
    public String companionBaseName(String baseName) {
        return baseName;
    }

    @Override
    public void call(Parameters parameters, Metadata combinedMetadata, Cipher cipher, InputStream in, OutputStream out) throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, MacVerificationFailedException, NoSuchAlgorithmException, NoSuchProviderException {
        logger.debug("Decrypting file…");
        var key = new SecretKeySpec(parameters.getKeyData().getCipherKey().array(), combinedMetadata.getCipherAlgorithm().toString());
        logger.debug("Initializing {} cipher…", cipher.getAlgorithm());
        var iv = combinedMetadata.getInitializationVector();
        if (iv == null) {
            cipher.init(Cipher.DECRYPT_MODE, key);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv.array()));
        }
        logger.debug("Decrypting file…");
        InputStream stream = in;
        MacOutputStream macCalculator = null;
        if (combinedMetadata.getMac() != null) {
            var macKeyBytes = parameters.getKeyData().getMacKey();
            if (macKeyBytes == null) {
                logger.debug("Missing MAC key");
                throw new MacVerificationFailedException();
            }
            var macKey = new SecretKeySpec(macKeyBytes.array(), combinedMetadata.getMacAlgorithm().toString());
            var mac = Mac.getInstance(combinedMetadata.getMacAlgorithm().toString(), "BC");
            mac.init(macKey);
            macCalculator = new MacOutputStream(mac);
            stream = new TeeInputStream(stream, macCalculator);
        }
        try (var outputStream = new CipherOutputStream(out, cipher)) {
            stream.transferTo(outputStream);
        }
        if (macCalculator != null) {
            macCalculator.close();
            if (Arrays.areEqual(combinedMetadata.getMac().array(), macCalculator.getMac())) {
                logger.debug("The MAC {} seems to be valid", Hex.toHexString(macCalculator.getMac()));
            } else {
                throw new MacVerificationFailedException();
            }
        }
    }
}
