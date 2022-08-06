package com.exploids.filecrypt;

import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Parameters;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.output.TeeOutputStream;
import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class EncryptionCommand implements SubCommand {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final ObjectMapper mapper;
    private Parameters parameters;
    private Cipher cipher;
    private Metadata combinedMetadata;
    private VerificationCalculator verificationCalculator;

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
    public OutputStream call(Parameters parameters, Metadata combinedMetadata, Cipher cipher, OutputStream out) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
        this.parameters = parameters;
        this.combinedMetadata = combinedMetadata;
        this.cipher = cipher;
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
        if (combinedMetadata.getVerification() != null) {
            var verificationAlgorithm = combinedMetadata.getVerificationAlgorithm();
            if (verificationAlgorithm.getKeyAlgorithmName() == null) {
                logger.debug("Selected verification algorithm {} is a message digest", verificationAlgorithm);
                var messageDigest = MessageDigest.getInstance(verificationAlgorithm.toString(), "BC");
                verificationCalculator = new MessageDigestOutputStream(messageDigest);
            } else {
                logger.debug("Selected verification algorithm {} is a MAC", verificationAlgorithm);
                var keyGenerator = KeyGenerator.getInstance(verificationAlgorithm.getKeyAlgorithmName(), "BC");
                logger.debug("Generating {} key…", verificationAlgorithm);
                var macKey = keyGenerator.generateKey();
                parameters.getKeyData().setVerificationKey(ByteBuffer.wrap(macKey.getEncoded()));
                var mac = Mac.getInstance(verificationAlgorithm.toString(), "BC");
                mac.init(macKey);
                verificationCalculator = new MacOutputStream(mac);
            }
            stream = new TeeOutputStream(stream, verificationCalculator);
        }
        logger.debug("Initializing cipher…");
        logger.info("Actual key size: {}", secretKey.getEncoded().length * 8);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return new CipherOutputStream(stream, cipher);
    }

    @Override
    public void doFinal() throws IOException {
        if (verificationCalculator != null) {
            combinedMetadata.setVerification(ByteBuffer.wrap(verificationCalculator.getEncoded()));
        }
        logger.debug("Encoding metadata…");
        var iv = cipher.getIV();
        if (iv != null) {
            combinedMetadata.setInitializationVector(ByteBuffer.wrap(iv));
        }
        try (var metadataOut = Files.newBufferedWriter(parameters.getMetadataFile())) {
            mapper.writeValue(metadataOut, combinedMetadata);
        }
        logger.debug("Encoding key…");
        try (var keyOut = Files.newBufferedWriter(parameters.getKeyFile())) {
            mapper.writeValue(keyOut, parameters.getKeyData());
        }
    }
}
