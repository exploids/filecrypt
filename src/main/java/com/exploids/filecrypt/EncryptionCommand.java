package com.exploids.filecrypt;

import com.exploids.filecrypt.exception.InsecureException;
import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Parameters;
import com.exploids.filecrypt.utility.ConsumingOutputStream;
import com.exploids.filecrypt.utility.FileCleanup;
import com.exploids.filecrypt.utility.MacOutputStream;
import com.exploids.filecrypt.utility.MessageDigestOutputStream;
import com.exploids.filecrypt.utility.SignatureOutputStream;
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
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class EncryptionCommand implements SubCommand {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final ObjectMapper mapper;
    private Parameters parameters;
    private Cipher cipher;
    private Metadata metadata;
    private FileCleanup cleanup;
    private ConsumingOutputStream<byte[]> verificationCalculator;
    private Signature signature;

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
    public void init(Parameters parameters, Metadata combinedMetadata, Cipher cipher, FileCleanup cleanup) {
        this.parameters = parameters;
        this.metadata = combinedMetadata;
        this.cipher = cipher;
        this.cleanup = cleanup;
    }

    @Override
    public void check() throws InsecureException {
        var check = new SecurityCheck();
        check.checkAndThrow(metadata);
    }

    @Override
    public OutputStream call(OutputStream out) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException {
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
            logger.debug("The key has been written to {}.", keyFile.toAbsolutePath());
        } else {
            secretKey = new SecretKeySpec(key.array(), algorithm.toString());
            logger.debug("Using provided key");
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
            logger.debug("Added verification step");
        }
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        logger.debug("Initialized cipher");
        stream = new CipherOutputStream(stream, cipher);
        if (metadata.getSignature() != null) {
            var encodedPrivateKey = parameters.getSignaturePrivateKey();
            PrivateKey privateKey;
            if (encodedPrivateKey == null) {
                var generator = KeyPairGenerator.getInstance("DSA", "BC");
                generator.initialize(2048);
                var keyPair = generator.generateKeyPair();
                privateKey = keyPair.getPrivate();
                metadata.setSignaturePublicKey(ByteBuffer.wrap(keyPair.getPublic().getEncoded()));
                parameters.setSignaturePrivateKey(ByteBuffer.wrap(privateKey.getEncoded()));
            } else {
                var keyFact = KeyFactory.getInstance("DSA", "BC");
                privateKey = keyFact.generatePrivate(new PKCS8EncodedKeySpec(encodedPrivateKey.array()));
            }
            signature = Signature.getInstance("SHA256withDSA", "BC");
            signature.initSign(privateKey);
            stream = new TeeOutputStream(stream, new SignatureOutputStream(signature));
        }
        return stream;
    }

    @Override
    public void doFinal() throws IOException, SignatureException {
        if (verificationCalculator != null) {
            metadata.setVerification(ByteBuffer.wrap(verificationCalculator.getResult()));
        }
        if (signature != null) {
            metadata.setSignature(ByteBuffer.wrap(signature.sign()));
        }
        logger.debug("Encoding metadata…");
        var iv = cipher.getIV();
        if (iv != null) {
            metadata.setInitializationVector(ByteBuffer.wrap(iv));
        }
        try (var metadataOut = cleanup.newBufferedWriter(parameters.getMetadataFile())) {
            mapper.writeValue(metadataOut, metadata);
        }
        logger.debug("Encoding key…");
        try (var keyOut = cleanup.newBufferedWriter(parameters.getKeyFile())) {
            mapper.writeValue(keyOut, parameters.getKeyData());
        }
    }
}
