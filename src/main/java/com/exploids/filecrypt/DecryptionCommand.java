package com.exploids.filecrypt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.FilenameUtils;
import org.bouncycastle.crypto.io.InvalidCipherTextIOException;
import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class DecryptionCommand implements SubCommand {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final Parameters parameters;

    private final Metadata combinedMetadata;
    private final Cipher cipher;

    public DecryptionCommand(Parameters parameters, Metadata combinedMetadata, Cipher cipher) {
        this.parameters = parameters;
        this.combinedMetadata = combinedMetadata;
        this.cipher = cipher;
    }

    @Override
    public Path resolveOutput(Path base, String baseName) {
        return base.resolveSibling(baseName + "_dec");
    }

    @Override
    public void call(InputStream in, OutputStream out) throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, InvalidAlgorithmParameterException {
        var file = parameters.getFile();
        String baseName;
        Path base;
        if (file == null) {
            baseName = "stdin";
            base = Paths.get(baseName);
        } else {
            baseName = FilenameUtils.removeExtension(file.getFileName().toString());
            base = file;
        }
        var keyFile = parameters.getKeyFile();
        if (keyFile == null) {
            keyFile = base.resolveSibling(baseName + "_key.txt");
        }
        logger.debug("Decrypting file…");
        SecretKey key = null;
        logger.debug("Trying to read key from {}…", keyFile.toAbsolutePath());
        try {
            byte[] keyBytes = Hex.decode(Files.readString(keyFile));
            key = new SecretKeySpec(keyBytes, combinedMetadata.getAlgorithm().toString());
            logger.debug("Read {} bit key", keyBytes.length * 8);
        } catch (NoSuchFileException e) {
            logger.debug("Key file does not exist");
        }
        logger.debug("Initializing cipher…");
        var iv = combinedMetadata.getInitializationVector();
        if (iv == null) {
            cipher.init(Cipher.DECRYPT_MODE, key);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        }
        logger.debug("Decrypting file…");
        try (var outputStream = new CipherOutputStream(out, cipher)) {
            in.transferTo(outputStream);
        }
    }
}
