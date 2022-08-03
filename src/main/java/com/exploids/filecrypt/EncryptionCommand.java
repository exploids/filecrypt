package com.exploids.filecrypt;

import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Parameters;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.jcajce.JceCMSMacCalculatorBuilder;
import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.bouncycastle.operator.DefaultMacAlgorithmIdentifierFinder;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.util.io.TeeOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class EncryptionCommand implements SubCommand {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final ObjectMapper mapper;

    public EncryptionCommand(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public String outputBaseName(String baseName) {
        return baseName + "_encrypted";
    }

    @Override
    public String companionBaseName(String baseName) {
        return outputBaseName(baseName);
    }

    @Override
    public void call(Parameters parameters, Metadata combinedMetadata, Cipher cipher, InputStream in, OutputStream out) throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, CMSException {
        var metadataFile = parameters.getMetadataFile();
        var keyFile = parameters.getKeyFile();
        var key = parameters.getKeyData().getCipherKey();
        var algorithm = combinedMetadata.getCipherAlgorithm();
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
            parameters.getKeyData().setCipherKey(ByteBuffer.wrap(secretKey.getEncoded()));
            logger.info("The key has been written to {}", keyFile.toAbsolutePath());
        } else {
            logger.debug("Using provided key");
            secretKey = new SecretKeySpec(key.array(), algorithm.toString());
        }
        var stream = out;
        MacOutputStream macCalculator = null;
        if (combinedMetadata.getMac() != null) {
            var keyGenerator = KeyGenerator.getInstance(combinedMetadata.getMacAlgorithm().getKeyAlgorithmName(), "BC");
            logger.debug("Generating {} key…", combinedMetadata.getMacAlgorithm());
            var macKey = keyGenerator.generateKey();
            parameters.getKeyData().setMacKey(ByteBuffer.wrap(macKey.getEncoded()));
            var mac = Mac.getInstance(combinedMetadata.getMacAlgorithm().toString(), "BC");
            mac.init(macKey);
            macCalculator = new MacOutputStream(mac);
            stream = new TeeOutputStream(stream, macCalculator);
        }
        performEncryption(in, stream, cipher, secretKey);
        if (macCalculator != null) {
            combinedMetadata.setMac(ByteBuffer.wrap(macCalculator.getMac()));
        }
        logger.debug("Encoding metadata…");
        combinedMetadata.setInitializationVector(ByteBuffer.wrap(cipher.getIV()));
        try (var metadataOut = Files.newBufferedWriter(metadataFile)) {
            mapper.writeValue(metadataOut, combinedMetadata);
        }
        logger.debug("Encoding key…");
        try (var keyOut = Files.newBufferedWriter(parameters.getKeyFile())) {
            mapper.writeValue(keyOut, parameters.getKeyData());
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
