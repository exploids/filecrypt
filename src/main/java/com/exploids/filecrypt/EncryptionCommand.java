package com.exploids.filecrypt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.FilenameUtils;
import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class EncryptionCommand implements SubCommand {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final ObjectMapper mapper;
    private final Parameters parameters;

    private final Metadata combinedMetadata;
    private final Cipher cipher;

    public EncryptionCommand(ObjectMapper mapper, Parameters parameters, Metadata combinedMetadata, Cipher cipher) {
        this.mapper = mapper;
        this.parameters = parameters;
        this.combinedMetadata = combinedMetadata;
        this.cipher = cipher;
    }

    @Override
    public Path resolveOutput(Path base, String baseName) {
        return base.resolveSibling(baseName + "_enc");
    }

    @Override
    public void call(InputStream in, OutputStream out) throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
        var file = parameters.getFile();
        var metadataFile = parameters.getMetadataFile();
        var keyFile = parameters.getKeyFile();
        var key = parameters.getKeyData().getCipherKey();
        String baseName;
        Path base;
        if (file == null) {
            baseName = "stdin";
            base = Paths.get(baseName);
        } else {
            baseName = FilenameUtils.removeExtension(file.getFileName().toString());
            base = file;
        }
        if (metadataFile == null) {
            metadataFile = base.resolveSibling(baseName + "_enc_meta.yaml");
        }
        if (keyFile == null) {
            keyFile = base.resolveSibling(baseName + "_enc_key.txt");
        }
        var algorithm = combinedMetadata.getAlgorithm();
        SecretKey secretKey;
        if (key == null) {
            logger.debug("Creating {} key generator…", algorithm);
            var keyGenerator = KeyGenerator.getInstance(algorithm.toString(), "BC");
            if (combinedMetadata.getKeySize() > 0) {
                keyGenerator.init(combinedMetadata.getKeySize());
            }
            logger.debug("Generating {} key…", algorithm);
            secretKey = keyGenerator.generateKey();
            combinedMetadata.setKeySize(secretKey.getEncoded().length * 8);
            logger.debug("Generated {} bit key", secretKey.getEncoded().length * 8);
            logger.debug("Writing key to {}…", keyFile.toAbsolutePath());
            Files.writeString(keyFile, Hex.toHexString(secretKey.getEncoded()));
            logger.debug("Wrote key");
            logger.info("The key has been written to {}", keyFile.toAbsolutePath());
        } else {
            logger.debug("Using provided key");
            secretKey = new SecretKeySpec(key.array(), algorithm.toString());
        }
        performEncryption(in, out, cipher, secretKey);
        logger.debug("Encoding metadata…");
        combinedMetadata.setInitializationVector(cipher.getIV());
        try (var metadataOut = Files.newBufferedWriter(metadataFile)) {
            mapper.writeValue(metadataOut, combinedMetadata);
        }
    }

    private void performEncryption(InputStream in, OutputStream out, Cipher cipher, SecretKey key) throws IOException, InvalidKeyException {
        logger.debug("Initializing cipher…");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        logger.debug("Encrypting file…");
        try (var cipherOut = new CipherOutputStream(out, cipher)) {
            in.transferTo(cipherOut);
        }
        logger.debug("Encryption complete");
    }
}
