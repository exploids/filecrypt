package com.exploids.filecrypt;

import com.exploids.fancyprinter.AnsiPrinter;
import com.exploids.fancyprinter.Color;
import com.exploids.fancyprinter.FancyPrinter;
import com.exploids.fancyprinter.PlainPrinter;
import com.exploids.filecrypt.exception.FileCryptException;
import com.exploids.filecrypt.exception.MacVerificationFailedException;
import com.exploids.filecrypt.model.Algorithm;
import com.exploids.filecrypt.model.BlockMode;
import com.exploids.filecrypt.model.ExitCode;
import com.exploids.filecrypt.model.KeyData;
import com.exploids.filecrypt.model.MacAlgorithm;
import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Padding;
import com.exploids.filecrypt.model.Parameters;
import com.exploids.filecrypt.serialization.HexByteBufferConverter;
import com.exploids.filecrypt.serialization.SpacedNamingStrategy;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.io.FilenameUtils;
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
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
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

    private final FancyPrinter standardOutput;

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
            standardOutput = new AnsiPrinter(System.out);
            errorOutput = new AnsiPrinter(System.err);
        } else {
            standardOutput = new PlainPrinter(System.out);
            errorOutput = new PlainPrinter(System.err);
        }
        if (verbose) {
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug");
            System.setProperty("org.slf4j.simpleLogger.showThreadName", "true");
            System.setProperty("org.slf4j.simpleLogger.showLogName", "true");
        } else  {
            System.setProperty("org.slf4j.simpleLogger.showThreadName", "false");
            System.setProperty("org.slf4j.simpleLogger.showLogName", "false");
        }
    }

    @Option(names = {"-v", "--verbose"})
    private boolean verbose;

    @Option(names = {"-d", "--decrypt"})
    private boolean decrypt;

    @CommandLine.ArgGroup(exclusive = false)
    private Parameters parameters;

    private Metadata combinedMetadata;

    private void printCheckNice(String key, Object... parameters) {
        printCheckBullet(Color.GREEN, '+', key, parameters);
    }

    private void printCheckWarn(String key, Object... parameters) {
        printCheckBullet(Color.YELLOW, '~', key, parameters);
    }

    private void printCheckFail(String key, Object... parameters) {
        printCheckBullet(Color.RED, '-', key, parameters);
    }

    private void printCheckBullet(Color color, char symbol, String key, Object... parameters) {
        standardOutput.color(color);
        standardOutput.getPrintStream().print("(");
        standardOutput.getPrintStream().print(symbol);
        standardOutput.getPrintStream().print(") ");
        standardOutput.getPrintStream().printf(messages.getString(key), parameters);
        standardOutput.resetNewLine();
    }

    @Override
    public Integer call() {
        return callAndCatch().getCode();
    }

    private ExitCode callAndCatch() {
        try {
            return callAndThrow();
        } catch (InvalidKeyException e) {
            logger.error("invalid key", e);
            if (e.getMessage().equals("no IV set when one expected")) {
                error("An IV is required, but was not provided!");
                errorHelp("Did you select the correct metadata file?");
                return ExitCode.FAILURE;
            } else {
                error("A key is required, but was not provided!");
                // errorHelp("Does %s exist?", keyFile.toAbsolutePath());
                return ExitCode.KEY_ERROR;
            }
        } catch (InvalidCipherTextIOException e) {
            logger.error("Invalid cipher text", e);
            error("Failed to decrypt the file due to invalid cipher text!");
            errorHelp("Did you select the correct key?");
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
        } catch (MacVerificationFailedException e) {
            logger.error("The file contents could not be authenticated");
            logger.debug("The MAC does not match", e);
            return ExitCode.MAC_VERIFICATION_FAILED;
        } catch (NoSuchAlgorithmException | CMSException | NoSuchProviderException | FileCryptException e) {
            logger.error("An unexpected error occurred", e);
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
            if (!secure) {
                logger.error("Not all parameters are secure and insecure encryption is not allowed");
                return ExitCode.FAILURE;
            }
        }
        try (var in = file == null ? System.in : Files.newInputStream(file)) {
            try (var out = output.length == 0 ? System.out : Files.newOutputStream(output[0])) {
                command.call(parameters, combinedMetadata, createCipher(combinedMetadata), in, out);
            }
        }
        logger.info("The output has been written to {}", output.length == 0 ? "the standard output" : output[0].toAbsolutePath());
        return ExitCode.OK;
    }

    private boolean checkSecure() {
        boolean secure = true;
        if (combinedMetadata.getCipherAlgorithm() == Algorithm.AES) {
            printCheckNice("other.check.algorithm.secure", combinedMetadata.getCipherAlgorithm());
        } else {
            printCheckFail("other.check.algorithm.insecure", combinedMetadata.getCipherAlgorithm());
            secure = false;
        }
        if (combinedMetadata.getPadding() == Padding.ZERO_BYTE) {
            printCheckFail("other.check.padding.insecure", combinedMetadata.getPadding());
            secure = false;
        } else {
            printCheckNice("other.check.padding.secure", combinedMetadata.getPadding());
        }
        if (combinedMetadata.getInitializationVector() != null) {
            printCheckWarn("other.check.iv.given", Hex.toHexString(combinedMetadata.getInitializationVector().array()));
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
        combinedMetadata.setBlockMode(BlockMode.CBC);
        combinedMetadata.setPadding(Padding.PKCS7);
        combinedMetadata.setMacAlgorithm(MacAlgorithm.HMACSHA256);
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
            try (var in = Files.newBufferedReader(metadataFile)) {
                var keyData = mapper.readValue(in, KeyData.class);
                if (parameters.getKeyData().getCipherKey() == null) {
                    parameters.getKeyData().setCipherKey(keyData.getCipherKey());
                }
                if (parameters.getKeyData().getMacKey() == null) {
                    parameters.getKeyData().setMacKey(keyData.getMacKey());
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

    private void printMissingEntryError(String entryName) {
        error("Missing %s entry in TAR archive!", entryName);
        errorHelp("Are you sure you selected the correct TAR archive?");
        errorHelp("Are you sure the TAR archive is not corrupt?");
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
        var cipherName = String.format("%s/%s/%s", metadata.getCipherAlgorithm(), metadata.getBlockMode(), metadata.getPadding().getAlgorithmName());
        logger.debug("Creating {} cipher…", cipherName);
        return Cipher.getInstance(cipherName, "BC");
    }

    private TarArchiveEntry createEntryWithSize(String name, long size) {
        var entry = new TarArchiveEntry(name);
        entry.setSize(size);
        return entry;
    }
}
