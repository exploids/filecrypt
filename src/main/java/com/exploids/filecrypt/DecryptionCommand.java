package com.exploids.filecrypt;

import com.exploids.filecrypt.exception.FileCryptException;
import com.exploids.filecrypt.exception.InsecureException;
import com.exploids.filecrypt.exception.InvalidSignatureException;
import com.exploids.filecrypt.exception.MissingMacKeyException;
import com.exploids.filecrypt.exception.VerificationFailedException;
import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Parameters;
import com.exploids.filecrypt.utility.ConsumingOutputStream;
import com.exploids.filecrypt.utility.FileCleanup;
import com.exploids.filecrypt.utility.MacOutputStream;
import com.exploids.filecrypt.utility.MessageDigestOutputStream;
import com.exploids.filecrypt.utility.SignatureOutputStream;
import org.apache.commons.io.output.TeeOutputStream;
import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class DecryptionCommand implements SubCommand {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private Parameters parameters;
    private Cipher cipher;
    private Metadata metadata;
    private ConsumingOutputStream<byte[]> verificationCalculator;
    private Signature signature;

    @Override
    public String outputBaseName(String baseName) {
        return baseName + "_decrypted";
    }

    @Override
    public String companionBaseName(String baseName) {
        return baseName;
    }

    @Override
    public void init(Parameters parameters, Metadata combinedMetadata, Cipher cipher, FileCleanup cleanup) {
        this.parameters = parameters;
        this.metadata = combinedMetadata;
        this.cipher = cipher;
    }

    @Override
    public void check() throws InsecureException {
    }

    @Override
    public OutputStream call(SecretKey cipherKey, OutputStream out) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, FileCryptException, InvalidKeySpecException {
        logger.debug("Decrypting file…");
        logger.debug("Initializing {} cipher…", cipher.getAlgorithm());
        var iv = metadata.getInitializationVector();
        if (iv == null) {
            cipher.init(Cipher.DECRYPT_MODE, cipherKey);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, cipherKey, new IvParameterSpec(iv.array()));
        }
        logger.debug("Decrypting file…");
        var stream = out;
        if (metadata.getSignature() != null) {
            signature = Signature.getInstance("SHA256withDSA", "BC");
            var keyFact = KeyFactory.getInstance("DSA", "BC");
            var publicKey = keyFact.generatePublic(new X509EncodedKeySpec(metadata.getSignaturePublicKey().array()));
            signature.initVerify(publicKey);
            stream = new TeeOutputStream(stream, new SignatureOutputStream(signature));
        }
        stream = new CipherOutputStream(stream, cipher);
        if (metadata.getVerification() != null) {
            var verificationAlgorithm = metadata.getVerificationAlgorithm();
            if (verificationAlgorithm.getKeyAlgorithmName() == null) {
                logger.debug("Selected verification algorithm {} is a message digest", verificationAlgorithm);
                var messageDigest = MessageDigest.getInstance(verificationAlgorithm.toString(), "BC");
                verificationCalculator = new MessageDigestOutputStream(messageDigest);
            } else {
                logger.debug("Selected verification algorithm {} is a MAC", verificationAlgorithm);
                var macKeyBytes = parameters.getKeyData().getVerificationKey();
                if (macKeyBytes == null) {
                    logger.debug("Missing MAC key");
                    throw new MissingMacKeyException();
                }
                var macKey = new SecretKeySpec(macKeyBytes.array(), metadata.getVerificationAlgorithm().toString());
                var mac = Mac.getInstance(metadata.getVerificationAlgorithm().toString(), "BC");
                mac.init(macKey);
                verificationCalculator = new MacOutputStream(mac);
            }
            stream = new TeeOutputStream(stream, verificationCalculator);
        }
        return stream;
    }

    @Override
    public void doFinal() throws VerificationFailedException, SignatureException, InvalidSignatureException {
        if (verificationCalculator != null) {
            var expected = metadata.getVerification().array();
            var actual = verificationCalculator.getResult();
            if (Arrays.areEqual(expected, actual)) {
                logger.debug("The MAC/hash {} seems to be valid", Hex.toHexString(verificationCalculator.getResult()));
            } else {
                throw new VerificationFailedException(expected, actual);
            }
        }
        if (signature != null) {
            if (!signature.verify(metadata.getSignature().array())) {
                throw new InvalidSignatureException();
            }
        }
    }
}
