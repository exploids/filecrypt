package com.exploids.filecrypt;

import com.exploids.filecrypt.exception.InsecureException;
import com.exploids.filecrypt.model.ExitCode;
import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Parameters;
import com.exploids.filecrypt.utility.MacOutputStream;
import com.exploids.filecrypt.utility.MessageDigestOutputStream;
import com.exploids.filecrypt.utility.VerificationCalculator;
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
    private Metadata metadata;
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
    public void init(Parameters parameters, Metadata combinedMetadata, Cipher cipher) {
        this.parameters = parameters;
        this.metadata = combinedMetadata;
        this.cipher = cipher;
    }

    @Override
    public void check() throws InsecureException {
        var check = new SecurityCheck();
        check.checkAndThrow(metadata);
    }

    @Override
    public OutputStream call(OutputStream out) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        var keyFile = parameters.getKeyFile();
        var key = parameters.getKeyData().getCipherKey();
        var algorithm = metadata.getCipherAlgorithm();
        SecretKey secretKey;
        if (key == null) {
            logger.debug("Creating {} key generator…", algorithm);
            var keyGenerator = KeyGenerator.getInstance(algorithm.toString(), "BC");
            if (metadata.getKeySize() > 0) {
                keyGenerator.init(metadata.getKeySize());
            }
            logger.debug("Generating {} key…", algorithm);
            secretKey = keyGenerator.generateKey();
            metadata.setKeySize(secretKey.getEncoded().length * 8);
            logger.debug("Generated {} bit key", secretKey.getEncoded().length * 8);
            parameters.getKeyData().setCipherKey(ByteBuffer.wrap(secretKey.getEncoded()));
            logger.info("The key has been written to {}", keyFile.toAbsolutePath());
        } else {
            logger.debug("Using provided key");
            secretKey = new SecretKeySpec(key.array(), algorithm.toString());
        }
        var stream = out;
        if (metadata.getVerification() != null) {
            var verificationAlgorithm = metadata.getVerificationAlgorithm();
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
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return new CipherOutputStream(stream, cipher);
    }

    @Override
    public void doFinal() throws IOException {
        if (verificationCalculator != null) {
            metadata.setVerification(ByteBuffer.wrap(verificationCalculator.getEncoded()));
        }
        logger.debug("Encoding metadata…");
        var iv = cipher.getIV();
        if (iv != null) {
            metadata.setInitializationVector(ByteBuffer.wrap(iv));
        }
        try (var metadataOut = Files.newBufferedWriter(parameters.getMetadataFile())) {
            mapper.writeValue(metadataOut, metadata);
        }
        logger.debug("Encoding key…");
        try (var keyOut = Files.newBufferedWriter(parameters.getKeyFile())) {
            mapper.writeValue(keyOut, parameters.getKeyData());
        }
    }
}
