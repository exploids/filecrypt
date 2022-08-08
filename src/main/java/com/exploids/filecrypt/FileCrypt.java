package com.exploids.filecrypt;

import com.exploids.filecrypt.exception.FileCryptException;
import com.exploids.filecrypt.exception.InsecureException;
import com.exploids.filecrypt.exception.InvalidSignatureException;
import com.exploids.filecrypt.exception.MissingMacKeyException;
import com.exploids.filecrypt.exception.VerificationFailedException;
import com.exploids.filecrypt.model.Algorithm;
import com.exploids.filecrypt.model.BlockMode;
import com.exploids.filecrypt.model.ExitCode;
import com.exploids.filecrypt.model.KeyData;
import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Padding;
import com.exploids.filecrypt.model.Parameters;
import com.exploids.filecrypt.model.PasswordAlgorithm;
import com.exploids.filecrypt.model.VerificationAlgorithm;
import com.exploids.filecrypt.serialization.HexByteBufferConverter;
import com.exploids.filecrypt.serialization.SpacedNamingStrategy;
import com.exploids.filecrypt.utility.ByteCountFormat;
import com.exploids.filecrypt.utility.FileCleanup;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.crypto.io.InvalidCipherTextIOException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.ResourceBundle;
import java.util.concurrent.Callable;

/**
 * The filecrypt application.
 *
 * @author Luca Selinski
 */
@Command(name = "filecrypt", mixinStandardHelpOptions = true, version = "1.0.0", resourceBundle = "com.exploids.filecrypt.Messages")
public class FileCrypt implements Callable<Integer> {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * The resource bundle that contains all the localized messages to output.
     */
    private final ResourceBundle messages;

    private final ByteCountFormat byteFormat = new ByteCountFormat();

    private final ObjectMapper mapper;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public FileCrypt() {
        messages = ResourceBundle.getBundle("com.exploids.filecrypt.Messages");
        mapper = new ObjectMapper(new YAMLFactory()
                .disable(YAMLGenerator.Feature.WRITE_DOC_START_MARKER)
                .enable(YAMLGenerator.Feature.MINIMIZE_QUOTES))
                .setPropertyNamingStrategy(new SpacedNamingStrategy())
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    @Option(names = {"-d", "--decrypt"})
    private boolean decrypt;

    @Option(names = {"--insecure"})
    private boolean insecureAllowed;

    @CommandLine.ArgGroup(exclusive = false)
    private Parameters parameters;

    private Metadata metadata;
    private SecretKey cipherKey;

    @Override
    public Integer call() {
        try {
            return callAndCatch().getCode();
        } catch (Exception exception) {
            logger.error("An uncaught exception occurred.", exception);
            return ExitCode.FAILURE.getCode();
        }
    }

    private ExitCode callAndCatch() {
        try {
            return callAndThrow();
        } catch (InvalidKeyException e) {
            if (e.getMessage().equals("no IV set when one expected")) {
                logger.error("An IV is required, but was not provided. Did you select the correct metadata file?");
                return ExitCode.FAILURE;
            } else if (e.getMessage().startsWith("Key length not ")) {
                logger.error("The key size {} cannot be used with the {} cipher.", metadata.getKeySize(), metadata.getCipherAlgorithm());
                return ExitCode.KEY_ERROR;
            } else {
                logger.error("The key is invalid.", e);
                return ExitCode.KEY_ERROR;
            }
        } catch (InvalidCipherTextIOException e) {
            if (e.getCause() instanceof IllegalBlockSizeException) {
                if (metadata.getPadding() == Padding.NONE) {
                    logger.error("You selected {} padding which only works for specific file sizes. The file you selected does not seem to have a size that works with this padding mode. Please select a different padding mode to encrypt the file.", metadata.getPadding());
                } else {
                    logger.error("An illegal block size has been encountered.", e);
                }
            } else {
                logger.error("Failed to decrypt the file due to invalid cipher text. Did you specify the correct key?", e);
            }
            return ExitCode.FAILURE;
        } catch (NoSuchFileException e) {
            logger.error("The file {} does not exist.", e.getFile());
            return ExitCode.NO_SUCH_FILE;
        } catch (IOException e) {
            logger.error("There was an input/output error. This issue may be resolved by re-running the command.", e);
            return ExitCode.IO_ERROR;
        } catch (VerificationFailedException e) {
            logger.error("The file contents could not be authenticated. The expected {} was {}, the actual value is {}.", metadata.getVerificationAlgorithm(), Hex.toHexString(e.getExpected()), Hex.toHexString(e.getActual()));
            return ExitCode.VERIFICATION_FAILED;
        } catch (MissingMacKeyException e) {
            logger.error("You tried to verify a MAC without specifying the corresponding verification key. Without the key, the file contents cannot be verified. You can still decrypt the file by using the --insecure command line option.");
            return ExitCode.VERIFICATION_FAILED;
        } catch (InsecureException e) {
            logger.error("Insecure encryption is not allowed. If you want to risk insecure encryption, re-run the command with the --insecure command line option.");
            return ExitCode.INSECURE;
        } catch (InvalidSignatureException e) {
            logger.error("The signature could not be verified.");
            return ExitCode.INVALID_SIGNATURE;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | FileCryptException | NoSuchPaddingException |
                 InvalidAlgorithmParameterException | InvalidKeySpecException | SignatureException e) {
            logger.error("An unexpected error occurred.", e);
            return ExitCode.FAILURE;
        }
    }

    private ExitCode callAndThrow() throws NoSuchAlgorithmException, IOException, NoSuchPaddingException, NoSuchProviderException, FileCryptException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, SignatureException {
        var bouncyCastle = Security.getProvider("BC");
        if (bouncyCastle == null) {
            logger.error("BouncyCastle has not been found.");
            return ExitCode.FAILURE;
        } else {
            logger.debug("Found {}.", bouncyCastle.getInfo());
        }
        if (hasUnlimitedStrength()) {
            logger.debug("Unlimited strength is allowed.");
        } else {
            logger.error("Unlimited strength is not allowed.");
            return ExitCode.FAILURE;
        }
        SubCommand command;
        if (decrypt) {
            command = new DecryptionCommand();
        } else {
            command = new EncryptionCommand(mapper);
        }
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
        var metadataFile = parameters.getMetadataFile();
        if (metadataFile == null) {
            parameters.setMetadataFile(base.resolveSibling(command.companionBaseName(baseName) + "_meta.yaml"));
        }
        var keyFile = parameters.getKeyFile();
        if (keyFile == null) {
            parameters.setKeyFile(base.resolveSibling(command.companionBaseName(baseName) + "_key.yaml"));
        }
        var output = parameters.getOutput();
        if (output == null) {
            output = new Path[]{base.resolveSibling(command.outputBaseName(baseName))};
        }
        prepare();
        try (var cleanup = new FileCleanup()) {
            command.init(parameters, metadata, createCipher(metadata), cleanup);
            try {
                command.check();
            } catch (InsecureException e) {
                logger.warn("The following parameters are considered insecure: {}", e.getConcerns());
                if (!insecureAllowed) {
                    throw e;
                }
            }
            var cipherKeyEncoded = parameters.getKeyData().getCipherKey();
            if (cipherKeyEncoded != null) {
                cipherKey = new SecretKeySpec(cipherKeyEncoded.array(), metadata.getCipherAlgorithm().toString());
            }
            try (var in = file == null ? System.in : Files.newInputStream(file)) {
                try (var plainOut = output.length == 0 ? System.out : cleanup.newOutputStream(output[0])) {
                    try (var out = command.call(cipherKey, plainOut)) {
                        long size = file == null ? Long.MAX_VALUE : Files.size(file);
                        transferData(in, out, size);
                    }
                }
            }
            command.doFinal();
            cleanup.commit();
            logger.debug("The output has been written to {}.", output.length == 0 ? "the standard output" : output[0].toAbsolutePath());
        }
        return ExitCode.OK;
    }

    private void transferData(InputStream in, OutputStream out, long size) throws IOException {
        long transferred = 0;
        byte[] buffer = new byte[IOUtils.DEFAULT_BUFFER_SIZE];
        int read;
        var lastUpdate = System.currentTimeMillis();
        boolean didGiveProgress = false;
        while ((read = in.read(buffer)) >= 0) {
            out.write(buffer, 0, read);
            transferred += read;
            if (System.currentTimeMillis() - lastUpdate >= 5000) {
                lastUpdate += 5000;
                logger.info("Processed {} ({}%)", byteFormat.format(transferred), (int) ((double) transferred / size * 100));
                didGiveProgress = true;
            }
        }
        if (didGiveProgress) {
            logger.info("Processed {} (100%)", byteFormat.format(transferred));
        }
    }

    public static void main(String... args) {
        int exitCode = new CommandLine(new FileCrypt())
                .registerConverter(ByteBuffer.class, new HexByteBufferConverter())
                .execute(args);
        System.exit(exitCode);
    }

    private void prepare() throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        metadata = new Metadata();
        metadata.setCipherAlgorithm(Algorithm.AES);
        var file = parameters.getFile();
        if (file != null) {
            var metadataFile = parameters.getMetadataFile();
            logger.debug("Trying to read metadata file {}…", metadataFile.toAbsolutePath());
            try (var metaInput = Files.newBufferedReader(metadataFile)) {
                var fileMetadata = mapper.readValue(metaInput, Metadata.class);
                metadata.setFrom(fileMetadata);
                logger.debug("Read metadata file");
            } catch (NoSuchFileException e) {
                logger.debug("Could not find {}", metadataFile.toAbsolutePath());
            }
            var keyFile = parameters.getKeyFile();
            logger.debug("Trying to read key file {}…", keyFile.toAbsolutePath());
            try (var in = Files.newBufferedReader(keyFile)) {
                var keyData = mapper.readValue(in, KeyData.class);
                if (parameters.getKeyData().getCipherKey() == null) {
                    parameters.getKeyData().setCipherKey(keyData.getCipherKey());
                }
                if (parameters.getKeyData().getVerificationKey() == null) {
                    parameters.getKeyData().setVerificationKey(keyData.getVerificationKey());
                }
                logger.debug("Read key file");
            } catch (NoSuchFileException e) {
                logger.debug("Could not find {}", metadataFile.toAbsolutePath());
            }
        }
        var metadataArguments = parameters.getMetadata();
        if (metadataArguments != null) {
            metadata.setFrom(metadataArguments);
        }
        if (!metadata.getCipherAlgorithm().isStream()) {
            if (metadata.getBlockMode() == null) {
                metadata.setBlockMode(BlockMode.CBC);
            }
            if (metadata.getPadding() == null) {
                if (metadata.getBlockMode() == BlockMode.GCM) {
                    metadata.setPadding(Padding.NONE);
                } else {
                    metadata.setPadding(Padding.PKCS7);
                }
            }
        }
        if (metadata.getKeySize() == null) {
            metadata.setKeySize(256);
        }
        if (metadata.getVerificationAlgorithm() == null && metadata.getVerification() != null) {
            metadata.setVerificationAlgorithm(VerificationAlgorithm.HMACSHA256);
        }
        var password = parameters.getPassword();
        if (password != null) {
            if (metadata.getPasswordAlgorithm() == null) {
                metadata.setPasswordAlgorithm(PasswordAlgorithm.SCRYPT);
            }
            if (metadata.getPasswordSalt() == null) {
                var random = SecureRandom.getInstance("DEFAULT", "BC");
                var salt = new byte[metadata.getPasswordAlgorithm().getSaltSize()];
                random.nextBytes(salt);
                metadata.setPasswordSalt(ByteBuffer.wrap(salt));
            }
            if (metadata.getPasswordAlgorithm() == PasswordAlgorithm.SCRYPT) {
                if (metadata.getPasswordBlockSize() == null) {
                    metadata.setPasswordBlockSize(8);
                }
                if (metadata.getPasswordParallelization() == null) {
                    metadata.setPasswordParallelization(4);
                }
            }
            if (parameters.getKeyData().getCipherKey() == null) {
                var passwordKeyGenerator = new PasswordKeyGenerator();
                cipherKey = passwordKeyGenerator.generate(password, metadata);
            }
            Arrays.fill(password, (char) 0);
        }
    }

    private void listProviders() {
        Provider[] installedProvs = Security.getProviders();
        for (var provider : installedProvs) {
            System.out.print(provider.getName());
            System.out.print(": ");
            System.out.print(provider.getInfo());
            System.out.println();
            if ("BC".equals(provider.getName())) {
                providerDetails(provider);
            }
        }
    }

    private void providerDetails(Provider provider) {
        for (Object o : provider.keySet()) {
            String entry = (String) o;
            boolean isAlias = false;
            if (entry.startsWith("Alg.Alias")) {
                isAlias = true;
                entry = entry.substring("Alg.Alias".length() + 1);
            }
            String serviceName = entry.substring(0, entry.indexOf('.'));
            String name = entry.substring(serviceName.length() + 1);
            System.out.print("  " + serviceName + ": " + name);
            if (isAlias) {
                System.out.print(" (alias for " + provider.get("Alg.Alias." + entry) + ")");
            }
            System.out.println();
        }
    }

    public boolean hasUnlimitedStrength() throws NoSuchAlgorithmException {
        try {
            Cipher cipher = Cipher.getInstance("Blowfish/ECB/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[32], "Blowfish"));
            return true;
        } catch (NoSuchAlgorithmException e) {
            throw e;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Creates the {@link Cipher} described by the {@link Metadata}.
     *
     * @param metadata the metadata
     * @return the cipher
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     */
    Cipher createCipher(Metadata metadata) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        String cipherName;
        if (metadata.getCipherAlgorithm().isStream()) {
            cipherName = metadata.getCipherAlgorithm().toString();
        } else {
            cipherName = String.format("%s/%s/%s", metadata.getCipherAlgorithm(), metadata.getBlockMode(), metadata.getPadding().getAlgorithmName());
        }
        logger.debug("Creating {} cipher…", cipherName);
        return Cipher.getInstance(cipherName, "BC");
    }
}
