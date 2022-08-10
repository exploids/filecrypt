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
import com.exploids.filecrypt.serialization.HexByteBufferConverter;
import com.exploids.filecrypt.serialization.SpacedNamingStrategy;
import com.exploids.filecrypt.step.CipherStep;
import com.exploids.filecrypt.step.SaveDataStep;
import com.exploids.filecrypt.step.SignatureStep;
import com.exploids.filecrypt.step.VerificationStep;
import com.exploids.filecrypt.utility.DataTransfer;
import com.exploids.filecrypt.utility.FileCleanup;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import org.bouncycastle.crypto.io.InvalidCipherTextIOException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * The filecrypt application.
 *
 * @author Luca Selinski
 */
@Command(name = "filecrypt", mixinStandardHelpOptions = true, version = "1.0.0", resourceBundle = "com.exploids.filecrypt.Messages")
public class FileCrypt implements Callable<Integer> {
    /**
     * The logger for this class.
     */
    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * The object mapper used for (de-)serialization.
     */
    private final ObjectMapper mapper;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Creates a new filecrypt application instance.
     */
    public FileCrypt() {
        mapper = new ObjectMapper(new YAMLFactory()
                .disable(YAMLGenerator.Feature.WRITE_DOC_START_MARKER)
                .enable(YAMLGenerator.Feature.MINIMIZE_QUOTES))
                .setPropertyNamingStrategy(new SpacedNamingStrategy())
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    /**
     * Whether the file should be decrypted.
     */
    @Option(names = {"-d", "--decrypt"})
    private boolean decrypt;

    /**
     * All general filecrypt parameters.
     */
    @ArgGroup(validate = false, multiplicity = "1")
    private Parameters parameters;

    /**
     * The combined set of metadata read from the command line and related files.
     */
    private Metadata metadata;

    /**
     * The key to use for ciphers.
     */
    private SecretKey cipherKey;

    /**
     * Runs the filecrypt CLI.
     *
     * @param args all command line arguments
     */
    public static void main(String... args) {
        int exitCode = new CommandLine(new FileCrypt())
                .registerConverter(ByteBuffer.class, new HexByteBufferConverter())
                .execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() {
        try {
            return callAndCatch().getCode();
        } catch (Exception exception) {
            logger.error("An uncaught exception occurred.", exception);
            return ExitCode.FAILURE.getCode();
        }
    }

    /**
     * Executes filecrypt, catching most known exceptions and handling them appropriately.
     *
     * @return the exit code
     */
    private ExitCode callAndCatch() {
        try {
            return callAndThrow();
        } catch (InvalidKeyException e) {
            if (e.getMessage().equals("no IV set when one expected")) {
                logger.error("An IV is required, but was not provided. Did you select the correct metadata file?");
                return ExitCode.FAILURE;
            } else if (e.getMessage().startsWith("Key for algorithm null not suitable")) {
                logger.error("No key or password given, even though one was required. Did you select the correct key file? Did you forget to enter a password?");
                return ExitCode.KEY_ERROR;
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
            } else if (e.getCause() instanceof BadPaddingException) {
                logger.error("Failed to decrypt the file. Did you specify the correct key or password?");
            } else {
                logger.error("Failed to decrypt the file. Did you specify the correct key or password?", e);
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
        } catch (FileCryptException | GeneralSecurityException e) {
            logger.error("An unexpected error occurred.", e);
            return ExitCode.FAILURE;
        }
    }

    /**
     * Executes filecrypt, throwing exceptions.
     *
     * @return the exit code
     * @throws GeneralSecurityException if some parameters are inavlid
     * @throws IOException              if an I/O error occurs
     * @throws FileCryptException       if a filecrypt specific error occurs
     */
    private ExitCode callAndThrow() throws GeneralSecurityException, IOException, FileCryptException {
        if (!checkPreconditions()) {
            return ExitCode.FAILURE;
        }
        prepare();
        var file = parameters.getFile();
        var output = parameters.getOutput();
        var steps = new ArrayList<>(List.of(
                new SaveDataStep(),
                new SignatureStep(),
                new CipherStep(),
                new VerificationStep()
        ));
        var cipher = createCipher(metadata, parameters.getPassword() != null);
        var cipherKeyEncoded = parameters.getKeyData().getCipherKey();
        if (cipherKeyEncoded != null) {
            cipherKey = new SecretKeySpec(cipherKeyEncoded.array(), metadata.getCipherAlgorithm().toString());
        }
        if (!decrypt) {
            Collections.reverse(steps);
        }
        var actions = steps.stream()
                .filter(step -> step.applies(metadata))
                .map(step -> step.buildAction(parameters, metadata, cipher, cipherKey, decrypt))
                .toList();
        for (var action : actions) {
            action.begin();
        }
        try (var cleanup = new FileCleanup()) {
            try (var in = Files.newInputStream(file)) {
                try (var plainOut = cleanup.newOutputStream(output)) {
                    var stream = plainOut;
                    for (var action : actions) {
                        stream = action.call(stream);
                    }
                    try (var out = stream) {
                        var size = Files.size(file);
                        var dataTransfer = new DataTransfer();
                        dataTransfer.transferData(in, out, size);
                    }
                }
            }
            for (var action : actions) {
                action.end(mapper, cleanup);
            }
            cleanup.commit();
            logger.debug("The output has been written to {}.", output.toAbsolutePath());
        }
        return ExitCode.OK;
    }

    /**
     * Checks whether bouncy castle is properly installed.
     *
     * @return true if all preconditions are met
     * @throws NoSuchAlgorithmException if unlimited strength cannot be tested
     */
    private boolean checkPreconditions() throws NoSuchAlgorithmException {
        var bouncyCastle = Security.getProvider("BC");
        if (bouncyCastle == null) {
            logger.error("BouncyCastle has not been found.");
            return false;
        } else {
            logger.debug("Found {}.", bouncyCastle.getInfo());
        }
        if (hasUnlimitedStrength()) {
            logger.debug("Unlimited strength is allowed.");
        } else {
            logger.error("Unlimited strength is not allowed.");
            return false;
        }
        return true;
    }

    /**
     * Collects metadata and keys from various sources.
     *
     * @throws IOException              if an i/O error occurs
     * @throws GeneralSecurityException if some parameters are invalid
     */
    private void prepare() throws IOException, GeneralSecurityException {
        var file = parameters.getFile();
        var output = parameters.getOutput();
        var baseName = file.getFileName().toString();
        String outputBaseName;
        if (output == null) {
            if (decrypt) {
                if (baseName.endsWith(".bin")) {
                    outputBaseName = "decrypted_" + baseName.substring(0, baseName.length() - 4);
                } else {
                    outputBaseName = "decrypted_" + baseName;
                }
            } else {
                outputBaseName = baseName + ".bin";
            }
            parameters.setOutput(file.resolveSibling(outputBaseName));
        } else {
            outputBaseName = output.getFileName().toString();
        }
        var metadataFileGiven = parameters.getMetadataFile();
        var metadataFile = metadataFileGiven;
        if (metadataFileGiven == null) {
            metadataFile = file.resolveSibling(baseName + ".meta.yaml");
            parameters.setMetadataFile(file.resolveSibling(outputBaseName + ".meta.yaml"));
        }
        var keyFileGiven = parameters.getKeyFile();
        var keyFile = keyFileGiven;
        if (keyFileGiven == null) {
            keyFile = file.resolveSibling(baseName + ".key.yaml");
            parameters.setKeyFile(file.resolveSibling(outputBaseName + ".key.yaml"));
        }
        metadata = new Metadata();
        logger.debug("Trying to read metadata file {}…", metadataFile.toAbsolutePath());
        try (var metaInput = Files.newBufferedReader(metadataFile)) {
            var fileMetadata = mapper.readValue(metaInput, Metadata.class);
            metadata.setFrom(fileMetadata);
            logger.debug("Read metadata file");
        } catch (NoSuchFileException e) {
            logger.debug("Could not find {}", metadataFile.toAbsolutePath());
            if (metadataFileGiven != null) {
                throw e;
            }
        }
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
            if (keyFileGiven != null) {
                throw e;
            }
        }
        var metadataArguments = parameters.getMetadata();
        if (metadataArguments != null) {
            metadata.setFrom(metadataArguments);
        }
        var generator = new DefaultParameterGenerator();
        var password = parameters.getPassword();
        generator.generate(metadata, password != null);
        if (password != null) {
            if (parameters.getKeyData().getCipherKey() == null) {
                var passwordKeyGenerator = new PasswordKeyGenerator(3000);
                cipherKey = passwordKeyGenerator.generate(password, algorithmName(metadata.getPasswordAlgorithm(), metadata.getKeySize(), metadata.getCipherAlgorithm(), metadata.getBlockMode()), metadata);
            }
            Arrays.fill(password, (char) 0);
        }
    }

    /**
     * Checks whether unlimited strength is allowed.
     *
     * @return true, if unlimited strength is allowed, otherwise false
     * @throws NoSuchAlgorithmException if unlimited strength cannot be tested
     */
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
     * @param metadata      the metadata
     * @param passwordBased whether the encryption is password based
     * @return the cipher
     * @throws GeneralSecurityException if some parameters are invalid
     */
    private Cipher createCipher(Metadata metadata, boolean passwordBased) throws GeneralSecurityException {
        var cipherAlgorithm = metadata.getCipherAlgorithm();
        var passwordAlgorithm = metadata.getPasswordAlgorithm();
        var blockMode = metadata.getBlockMode();
        String cipherName;
        if (passwordBased && passwordAlgorithm != PasswordAlgorithm.SCRYPT) {
            cipherName = algorithmName(passwordAlgorithm, metadata.getKeySize(), cipherAlgorithm, blockMode);
        } else if (cipherAlgorithm.isStream()) {
            cipherName = cipherAlgorithm.toString();
        } else {
            cipherName = String.format("%s/%s/%s", cipherAlgorithm, blockMode, metadata.getPadding().getPaddingName());
        }
        logger.debug("Creating {} cipher.", cipherName);
        return Cipher.getInstance(cipherName, "BC");
    }

    /**
     * Builds the algorithm name for bouncy castle.
     *
     * @param passwordAlgorithm the password algorithm
     * @param keySize           the key size
     * @param cipherAlgorithm   the cipher algorithm
     * @param blockMode         the cipher block mode
     * @return the algorithm name
     */
    private String algorithmName(PasswordAlgorithm passwordAlgorithm, int keySize, Algorithm cipherAlgorithm, BlockMode blockMode) {
        if (passwordAlgorithm == PasswordAlgorithm.SCRYPT) {
            return "SCRYPT";
        } else if (cipherAlgorithm.isStream()) {
            return String.format("PBEWith%sAnd%dBit%s", passwordAlgorithm, keySize, cipherAlgorithm);
        } else {
            return String.format("PBEWith%sAnd%dBit%s-%s-BC", passwordAlgorithm, keySize, cipherAlgorithm, blockMode);
        }
    }
}
