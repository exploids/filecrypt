package com.exploids.filecrypt;

import com.exploids.fancyprinter.AnsiPrinter;
import com.exploids.fancyprinter.Color;
import com.exploids.fancyprinter.FancyPrinter;
import com.exploids.fancyprinter.PlainPrinter;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.io.FilenameUtils;
import org.bouncycastle.crypto.io.InvalidCipherTextIOException;
import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.ResourceBundle;
import java.util.concurrent.Callable;

/**
 * @author Luca Selinski
 */
@Command(name = "filecrypt", mixinStandardHelpOptions = true, version = "1.0.0", resourceBundle = "com.exploids.filecrypt.Messages")
public class FileCrypt implements Callable<Integer> {
    private final BouncyCastleProvider provider;

    private final ResourceBundle messages;

    private final ObjectMapper mapper;

    private final FancyPrinter standardOutput;

    private final FancyPrinter errorOutput;

    public FileCrypt() {
        provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        messages = ResourceBundle.getBundle("com.exploids.filecrypt.Messages");
        mapper = new ObjectMapper(new YAMLFactory()
                .disable(YAMLGenerator.Feature.WRITE_DOC_START_MARKER)
                .enable(YAMLGenerator.Feature.MINIMIZE_QUOTES));
        if (CommandLine.Help.Ansi.AUTO.enabled()) {
            standardOutput = new AnsiPrinter(System.out);
            errorOutput = new AnsiPrinter(System.err);
        } else {
            standardOutput = new PlainPrinter(System.out);
            errorOutput = new PlainPrinter(System.err);
        }
    }

    @Option(names = {"-v", "--verbose"})
    private boolean verbose;

    @Option(names = {"-i", "--input"})
    private Path file;

    @Option(names = {"-o", "--output"})
    private Path output;

    @Option(names = {"-k", "--key-file"})
    private Path keyFile;

    @Option(names = {"--key"})
    private ByteBuffer key;

    @Option(names = {"-m", "--metadata"})
    private Path metadataFile;

    @CommandLine.ArgGroup(exclusive = false)
    private Metadata metadataArguments;

    @Option(names = {"-p", "--password"}, description = "The password to use.", interactive = true)
    private char[] password;

    private Metadata combinedMetadata;

    @Command(name = "encrypt", aliases = {"e"}, mixinStandardHelpOptions = true)
    public Integer encrypt() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        prepare();
        String baseName;
        Path base;
        if (file == null) {
            baseName = "stdin";
            base = Paths.get(baseName);
        } else {
            baseName = file.getFileName().toString().replaceFirst("\\.\\S*$", "");
            base = file;
        }
        if (output == null) {
            output = base.resolveSibling(baseName + "_enc");
        }
        if (metadataFile == null) {
            metadataFile = base.resolveSibling(baseName + "_enc_meta.yaml");
        }
        if (keyFile == null) {
            keyFile = base.resolveSibling(baseName + "_enc_key.txt");
        }
        var algorithm = combinedMetadata.getAlgorithm();
        log("Creating %s key generator…", algorithm);
        var keyGenerator = KeyGenerator.getInstance(algorithm.toString(), provider);
        log("Generating key…", algorithm);
        var key = keyGenerator.generateKey();
        log("Generated %d bit key", key.getEncoded().length * 8);
        if (keyFile != null) {
            log("Writing key to %s…", keyFile.toAbsolutePath());
            Files.write(keyFile, key.getEncoded());
            log("Wrote key");
        }
        var cipher = createCipher(combinedMetadata);
        try (var stream = file == null ? System.in : Files.newInputStream(file)) {
            try (var outputStream = output == null ? System.out : Files.newOutputStream(output)) {
                performEncryption(stream, outputStream, cipher, key);
            }
        }
        log("Encryption complete");
        log("Encoding metadata…");
        combinedMetadata.setInitializationVector(cipher.getIV());
        var metadataEncoded = mapper.writeValueAsBytes(combinedMetadata);
        if (metadataFile != null) {
            try (var out = Files.newBufferedWriter(metadataFile)) {
                mapper.writeValue(out, combinedMetadata);
            }
        }
        log("Done");
        return ExitCode.OK.getCode();
    }

    /**
     * Performs the actual encryption.
     *
     * @param in     the clear text stream
     * @param out    the stream to write the encrypted data to
     * @param cipher the cipher to use
     * @param key    the key to use
     * @throws IOException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    void performEncryption(InputStream in, OutputStream out, Cipher cipher, SecretKey key) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        log("Initializing cipher…");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        log("Encrypting file…");
        try (var cipherOut = new CipherOutputStream(out, cipher)) {
            in.transferTo(cipherOut);
        }
        log("Encryption complete");
    }

    @Command(name = "decrypt", aliases = {"d"}, mixinStandardHelpOptions = true)
    public Integer decrypt() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        String baseName;
        Path base;
        if (file == null) {
            baseName = "stdin";
            base = Paths.get(baseName);
        } else {
            baseName = FilenameUtils.removeExtension(file.getFileName().toString());
            base = file;
        }
        if (output == null) {
            output = base.resolveSibling(baseName + "_dec");
        }
        if (metadataFile == null) {
            metadataFile = base.resolveSibling(baseName + "_meta.yaml");
        }
        if (keyFile == null) {
            keyFile = base.resolveSibling(baseName + "_key.txt");
        }
        prepare();
        log("Decrypting file…");
        SecretKey key = null;
        if (keyFile != null) {
            log("Trying to read key from %s…", keyFile.toAbsolutePath());
            try {
                byte[] keyBytes = Files.readAllBytes(keyFile);
                key = new SecretKeySpec(keyBytes, combinedMetadata.getAlgorithm().toString());
                log("Read %d bit key", keyBytes.length * 8);
            } catch (NoSuchFileException e) {
                log("Key file does not exist");
            }
        }
        var cipherName = String.format("%s/%s/%s", combinedMetadata.getAlgorithm(), combinedMetadata.getBlockMode(), combinedMetadata.getPadding());
        log("Creating %s cipher…", cipherName);
        var cipher = Cipher.getInstance(cipherName, provider);
        log("Initializing cipher…");
        try {
            var iv = combinedMetadata.getInitializationVector();
            if (iv == null) {
                cipher.init(Cipher.DECRYPT_MODE, key);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            }
        } catch (InvalidKeyException e) {
            if (e.getMessage().equals("no IV set when one expected")) {
                error("An IV is required, but was not provided!");
                errorHelp("Did you select the correct metadata file?");
                return ExitCode.FAILURE.getCode();
            } else if (key == null) {
                error("A key is required, but was not provided!");
                errorHelp("Does %s exist?", keyFile.toAbsolutePath());
                return ExitCode.KEY_ERROR.getCode();
            } else {
                throw e;
            }
        }
        log("Decrypting file…");
        try (var outputStream = new CipherOutputStream(output == null ? System.out : Files.newOutputStream(output), cipher)) {
            try (var encryptedInput = file == null ? System.in : Files.newInputStream(file)) {
                encryptedInput.transferTo(outputStream);
            }
        } catch (InvalidCipherTextIOException e) {
            error("Failed to decrypt the file due to invalid cipher text!");
            errorHelp("Did you select the correct key?");
            return ExitCode.FAILURE.getCode();
        }
        log("Done");
        return ExitCode.OK.getCode();
    }

    @Command(name = "check", aliases = {"c"}, mixinStandardHelpOptions = true)
    public Integer check() throws IOException {
        boolean insecure = false;
        prepare();
        if (combinedMetadata.getAlgorithm() == Algorithm.AES) {
            printCheckNice("other.check.algorithm.secure", combinedMetadata.getAlgorithm());
        } else {
            printCheckFail("other.check.algorithm.insecure", combinedMetadata.getAlgorithm());
            insecure = true;
        }
        if (combinedMetadata.getPadding() == Padding.ZERO_BYTE) {
            printCheckFail("other.check.padding.insecure", combinedMetadata.getPadding());
        } else {
            printCheckNice("other.check.padding.secure", combinedMetadata.getPadding());
            insecure = true;
        }
        if (combinedMetadata.getInitializationVector() != null) {
            printCheckWarn("other.check.iv.given", Hex.toHexString(combinedMetadata.getInitializationVector()));
        }
        return (insecure ? ExitCode.FAILURE : ExitCode.OK).getCode();
    }

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
    public Integer call() throws NoSuchAlgorithmException {
        var bouncyCastle = Security.getProvider("BC");
        if (bouncyCastle == null) {
            System.out.println(CommandLine.Help.Ansi.AUTO.string("@|red (-) BouncyCastle has not been found|@"));
        } else {
            System.out.println(CommandLine.Help.Ansi.AUTO.string("@|green (+) Found " + bouncyCastle.getInfo() + "|@"));
        }
        if (hasUnlimitedStrength()) {
            System.out.println(CommandLine.Help.Ansi.AUTO.string("@|green (+) Unlimited strength is allowed|@"));
        } else {
            System.out.println(CommandLine.Help.Ansi.AUTO.string("@|red (-) Unlimited strength is not allowed|@"));
        }
        return ExitCode.OK.getCode();
    }

    public static void main(String... args) {
        int exitCode = new CommandLine(new FileCrypt())
                .registerConverter(ByteBuffer.class, new HexByteBufferConverter())
                .execute(args);
        System.exit(exitCode);
    }

    private void prepare() throws IOException {
        combinedMetadata = new Metadata();
        combinedMetadata.setAlgorithm(Algorithm.AES);
        combinedMetadata.setBlockMode(BlockMode.CBC);
        combinedMetadata.setPadding(Padding.PKCS7);
        if (metadataFile != null) {
            log("Trying to read metadata file…");
            try (var metaInput = Files.newBufferedReader(metadataFile)) {
                var fileMetadata = mapper.readValue(metaInput, Metadata.class);
                combinedMetadata.setFrom(fileMetadata);
                log("Read metadata");
            } catch (NoSuchFileException e) {
                log("Could not find %s", metadataFile.toAbsolutePath());
            }
        }
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

    /**
     * Formats and logs a single message.
     * Uses {@link System#err} to not interfere with the standard output.
     *
     * @param message    the message
     * @param parameters the message parameters
     */
    private void log(String message, Object... parameters) {
        if (verbose) {
            errorOutput.printf(Color.CYAN, message, parameters);
            errorOutput.getPrintStream().println();
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
    Cipher createCipher(Metadata metadata) throws NoSuchPaddingException, NoSuchAlgorithmException {
        var cipherName = String.format("%s/%s/%s", metadata.getAlgorithm(), metadata.getBlockMode(), metadata.getPadding());
        log("Creating %s cipher…", cipherName);
        return Cipher.getInstance(cipherName, provider);
    }

    private TarArchiveEntry createEntryWithSize(String name, long size) {
        var entry = new TarArchiveEntry(name);
        entry.setSize(size);
        return entry;
    }
}
