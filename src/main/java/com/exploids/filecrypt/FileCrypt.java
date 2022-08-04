package com.exploids.filecrypt;

import com.exploids.fancyprinter.AnsiPrinter;
import com.exploids.fancyprinter.Color;
import com.exploids.fancyprinter.FancyPrinter;
import com.exploids.fancyprinter.PlainPrinter;
import com.exploids.filecrypt.exception.FileCryptException;
import com.exploids.filecrypt.exception.VerificationFailedException;
import com.exploids.filecrypt.model.Algorithm;
import com.exploids.filecrypt.model.BlockMode;
import com.exploids.filecrypt.model.ExitCode;
import com.exploids.filecrypt.model.KeyData;
import com.exploids.filecrypt.model.VerificationAlgorithm;
import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Padding;
import com.exploids.filecrypt.model.Parameters;
import com.exploids.filecrypt.serialization.HexByteBufferConverter;
import com.exploids.filecrypt.serialization.SpacedNamingStrategy;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.cms.CMSException;
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
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.text.DecimalFormat;
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

    private final ObjectMapper mapper;

    private final FancyPrinter errorOutput;

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
        if (CommandLine.Help.Ansi.AUTO.enabled()) {
            errorOutput = new AnsiPrinter(System.err);
        } else {
            errorOutput = new PlainPrinter(System.err);
        }
        if (debug) {
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug");
            System.setProperty("org.slf4j.simpleLogger.showThreadName", "true");
            System.setProperty("org.slf4j.simpleLogger.showLogName", "true");
        }
    }

    @Option(names = {"--debug"})
    private boolean debug;

    @Option(names = {"-d", "--decrypt"})
    private boolean decrypt;

    @Option(names = {"--insecure"})
    private boolean insecureAllowed;

    @CommandLine.ArgGroup(exclusive = false)
    private Parameters parameters;

    private Metadata combinedMetadata;

    @Override
    public Integer call() {
        return callAndCatch().getCode();
    }

    private ExitCode callAndCatch() {
        try {
            return callAndThrow();
        } catch (InvalidKeyException e) {
            if (e.getMessage().equals("no IV set when one expected")) {
                logger.error("An IV is required, but was not provided. Did you select the correct metadata file?");
                return ExitCode.FAILURE;
            } else if(e.getMessage().startsWith("Key length not ")) {
                logger.error("The key size {} cannot be used with the {} cipher.", combinedMetadata.getKeySize(), combinedMetadata.getCipherAlgorithm());
                return ExitCode.KEY_ERROR;
            } else {
                logger.error("The key is invalid.", e);
                return ExitCode.KEY_ERROR;
            }
        } catch (InvalidCipherTextIOException e) {
            if (e.getCause() instanceof IllegalBlockSizeException) {
                logger.error("An illegal block size has been encountered. Did you select NO padding, even though your plain text is not block-aligned?");
            } else {
                logger.error("Invalid cipher text", e);
                error("Failed to decrypt the file due to invalid cipher text!");
                errorHelp("Did you select the correct key?");
            }
            return ExitCode.FAILURE;
        } catch (InvalidAlgorithmParameterException e) {
            logger.error("InvalidAlgorithmParameterException", e);
            return ExitCode.FAILURE;
        } catch (NoSuchPaddingException e) {
            logger.error("NoSuchPaddingException", e);
            return ExitCode.FAILURE;
        } catch (NoSuchFileException e) {
            logger.error("The file {} does not exist", e.getFile());
            return ExitCode.NO_SUCH_FILE;
        } catch (IOException e) {
            logger.error("There was an IO error", e);
            return ExitCode.IO_ERROR;
        } catch (VerificationFailedException e) {
            logger.error("The file contents could not be authenticated");
            logger.debug("The MAC/hash does not match", e);
            return ExitCode.VERIFICATION_FAILED;
        } catch (NoSuchAlgorithmException | CMSException | NoSuchProviderException | FileCryptException e) {
            logger.error("An unexpected error occurred", e);
            return ExitCode.FAILURE;
        } catch (Exception e) {
            logger.error("An uncaught exception occurred", e);
            return ExitCode.FAILURE;
        }
    }

    private ExitCode callAndThrow() throws InvalidAlgorithmParameterException, IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, NoSuchPaddingException, CMSException, FileCryptException {
        var bouncyCastle = Security.getProvider("BC");
        if (bouncyCastle == null) {
            logger.error("BouncyCastle has not been found");
            return ExitCode.FAILURE;
        } else {
            logger.debug("Found {}", bouncyCastle.getInfo());
        }
        if (hasUnlimitedStrength()) {
            logger.debug("Unlimited strength is allowed");
        } else {
            logger.error("Unlimited strength is not allowed");
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
        if (!decrypt) {
            boolean secure = checkSecure();
            if (!secure && !insecureAllowed) {
                logger.error("Not all parameters are secure and insecure encryption is not allowed");
                return ExitCode.INSECURE;
            }
        }
        try (var in = file == null ? System.in : Files.newInputStream(file)) {
            try (var plainOut = output.length == 0 ? System.out : Files.newOutputStream(output[0])) {
                try (var out = command.call(parameters, combinedMetadata, createCipher(combinedMetadata), plainOut)) {
                    long size = file == null ? Long.MAX_VALUE : Files.size(file);
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
                            logger.info("Processed {} ({}%)", formatByteCount(transferred), (int) ((double) transferred / size * 100));
                            didGiveProgress = true;
                        }
                    }
                    if (didGiveProgress) {
                        logger.info("Processed {} (100%)", formatByteCount(transferred));
                    }
                }
            }
        }
        command.doFinal();
        logger.info("The output has been written to {}", output.length == 0 ? "the standard output" : output[0].toAbsolutePath());
        return ExitCode.OK;
    }

    private String formatByteCount(long size) {
        if (size <= 0) return "0 B";
        final String[] units = new String[]{"B", "kB", "MB", "GB", "TB", "PB", "EB"};
        int digitGroups = (int) (Math.log10(size) / Math.log10(1000));
        return new DecimalFormat("#,##0.#").format(size / Math.pow(1000, digitGroups)) + " " + units[digitGroups];
    }

    private boolean checkSecure() {
        boolean secure = true;
//        if (combinedMetadata.getCipherAlgorithm() != Algorithm.AES) {
//            logger.warn(messages.getString("other.check.algorithm.insecure"), combinedMetadata.getCipherAlgorithm());
//            secure = false;
//        }
        if (combinedMetadata.getBlockMode() == BlockMode.ECB) {
            logger.warn(messages.getString("other.check.blockMode.insecure"), combinedMetadata.getBlockMode());
            secure = false;
        }
        if (combinedMetadata.getPadding() == Padding.ZERO_BYTE) {
            logger.warn(messages.getString("other.check.padding.insecure"), combinedMetadata.getPadding());
            secure = false;
        }
        if (combinedMetadata.getInitializationVector() != null) {
            logger.warn(messages.getString("other.check.iv.given"), Hex.toHexString(combinedMetadata.getInitializationVector().array()));
        }
        return secure;
    }

    public static void main(String... args) {
        int exitCode = new CommandLine(new FileCrypt())
                .registerConverter(ByteBuffer.class, new HexByteBufferConverter())
                .execute(args);
        System.exit(exitCode);
    }

    private void prepare() throws IOException {
        combinedMetadata = new Metadata();
        combinedMetadata.setCipherAlgorithm(Algorithm.AES);
        var file = parameters.getFile();
        if (file != null) {
            var metadataFile = parameters.getMetadataFile();
            logger.debug("Trying to read metadata file {}…", metadataFile.toAbsolutePath());
            try (var metaInput = Files.newBufferedReader(metadataFile)) {
                var fileMetadata = mapper.readValue(metaInput, Metadata.class);
                combinedMetadata.setFrom(fileMetadata);
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
            combinedMetadata.setFrom(metadataArguments);
        }
        if (!combinedMetadata.getCipherAlgorithm().isStream()) {
            if (combinedMetadata.getBlockMode() == null) {
                combinedMetadata.setBlockMode(BlockMode.CBC);
            }
            if (combinedMetadata.getPadding() == null) {
                if (combinedMetadata.getBlockMode() == BlockMode.GCM) {
                    combinedMetadata.setPadding(Padding.NONE);
                } else {
                    combinedMetadata.setPadding(Padding.PKCS7);
                }
            }
        }
        if (combinedMetadata.getVerificationAlgorithm() == null && combinedMetadata.getVerification() != null) {
            combinedMetadata.setVerificationAlgorithm(VerificationAlgorithm.HMACSHA256);
        }
    }

    private void error(String message, Object... parameters) {
        errorOutput.printf(Color.RED, message, parameters);
        errorOutput.getPrintStream().println();
    }

    private void errorHelp(String message, Object... parameters) {
        errorOutput.printf(Color.YELLOW, message, parameters);
        errorOutput.getPrintStream().println();
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
