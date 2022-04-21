package com.exploids.filecrypt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.toml.TomlFactory;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.archivers.tar.TarFile;
import org.bouncycastle.crypto.io.InvalidCipherTextIOException;
import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.concurrent.Callable;

/**
 * @author Luca Selinski
 */
@Command(name = "filecrypt", mixinStandardHelpOptions = true, version = "1.0.0", description = """
        Encrypts or decrypts a file.""")
public class FileCrypt implements Callable<Integer> {
    private final String metadataEntryName = "meta.toml";
    private final BouncyCastleProvider provider;

    private final ObjectMapper mapper;

    public FileCrypt() {
        provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        mapper = new ObjectMapper(new TomlFactory());
    }

    @Option(names = {"-v", "--verbose"}, description = "Print a lot of stuff to the console.")
    private boolean verbose;

    @Option(names = {"-i", "--input"}, description = """
            The input file. If omitted, the standard input will be used. This is especially useful, if you want to pipe data into filecrypt.""")
    private Path file;

    @Option(names = {"-k", "--key"}, description = """
            The key file.""")
    private Path keyFile;

    @Option(names = {"-o", "--output"}, description = """
            The output file. If omitted, the standard output will be used. This is especially useful, if you want to pipe the output from filecrypt to somewhere else.""")
    private Path output;

    @Option(names = {"-m", "--metadata"}, description = """
            The file to use for metadata. If no file is given, the metadata will be bundled into a TAR-archive along with the encrypted data.""")
    private Path metadata;

    @Option(names = {"-a", "--algorithm"}, description = "The algorithm to use: ${COMPLETION-CANDIDATES}. (Default: ${DEFAULT-VALUE})")
    private Algorithm algorithm = Algorithm.AES;

    @Option(names = {"-b", "--block-mode"}, description = "The block mode to use: ${COMPLETION-CANDIDATES}. (Default: ${DEFAULT-VALUE})")
    private BlockMode blockMode = BlockMode.CBC;

    @Option(names = {"-p", "--password"}, description = "The password to use.", interactive = true)
    private char[] password;

    @Option(names = {"-d", "--padding"}, description = "The padding to use: ${COMPLETION-CANDIDATES}. (Default: ${DEFAULT-VALUE})")
    private Padding padding = Padding.PKCS7;

    @Command(name = "encrypt", aliases = {"e"}, mixinStandardHelpOptions = true)
    public Integer encrypt() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
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
        var cipher = createCipher();
        log("Initializing cipher…");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        log("Encrypting file…");
        try (var stream = file == null ? System.in : Files.newInputStream(file)) {
            var temporaryDataFile = Files.createTempFile("filecrypt", "");
            try (var outputStream = new CipherOutputStream(Files.newOutputStream(temporaryDataFile), cipher)) {
                stream.transferTo(outputStream);
            }
            log("Wrote encrypted data to %s", temporaryDataFile.toAbsolutePath());
            log("Encoding metadata…");
            var metadata = new Metadata();
            metadata.setAlgorithm(algorithm);
            metadata.setBlockMode(blockMode);
            metadata.setPadding(padding);
            metadata.setInitializationVector(cipher.getIV());
            var metadataEncoded = mapper.writeValueAsBytes(metadata);
            log("Encoded metadata (%d bytes)", metadataEncoded.length);
            log("Creating TAR archive…");
            try (var tarOutput = new TarArchiveOutputStream(output == null ? System.out : Files.newOutputStream(output))) {
                tarOutput.putArchiveEntry(createEntryWithSize(metadataEntryName, metadataEncoded.length));
                try (var metadataInput = new ByteArrayInputStream(metadataEncoded)) {
                    metadataInput.transferTo(tarOutput);
                }
                tarOutput.closeArchiveEntry();
                tarOutput.putArchiveEntry(createEntryWithSize("data", Files.size(temporaryDataFile)));
                try (var temporaryInput = Files.newInputStream(temporaryDataFile)) {
                    temporaryInput.transferTo(tarOutput);
                }
                tarOutput.closeArchiveEntry();
            }
            log("Done");
            return 0;
        }
    }

    @Command(name = "decrypt", aliases = {"d"}, mixinStandardHelpOptions = true)
    public Integer decrypt() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        SecretKey key = null;
        if (keyFile != null) {
            log("Reading key from %s…", keyFile.toAbsolutePath());
            try {
                byte[] keyBytes = Files.readAllBytes(keyFile);
                key = new SecretKeySpec(keyBytes, algorithm.toString());
                log("Read %d bit key", keyBytes.length * 8);
            } catch (NoSuchFileException e) {
                log("Key file does not exist, will generate new key");
            }
        }
        log("Decrypting file…");
        Path inputPath;
        if (file == null) {
            inputPath = Files.createTempFile("filecrypt", "");
            log("Writing input stream to temporary file %s…", inputPath.toAbsolutePath());
            try (var outputStream = Files.newOutputStream(inputPath)) {
                System.in.transferTo(outputStream);
            }
            log("Wrote temporary file");
        } else {
            inputPath = file;
        }
        try (var tarInput = new TarFile(inputPath)) {
            TarArchiveEntry metaEntry = null;
            TarArchiveEntry dataEntry = null;
            for (var entry : tarInput.getEntries()) {
                if (entry.getName().equals(metadataEntryName)) {
                    log("Found %s entry", metadataEntryName);
                    metaEntry = entry;
                } else if (entry.getName().equals("data")) {
                    log("Found data entry");
                    dataEntry = entry;
                } else {
                    log("Ignoring entry %s", entry.getName());
                }
            }
            if (metaEntry == null) {
                printMissingEntryError(metadataEntryName);
                return 1;
            }
            if (dataEntry == null) {
                printMissingEntryError("data");
                return 1;
            }
            Metadata metadata;
            log("Decoding metadata…");
            try (var metaInput = tarInput.getInputStream(metaEntry)) {
                metadata = mapper.readValue(metaInput, Metadata.class);
                log("Decoded metadata");
            }
            var cipherName = String.format("%s/%s/%s", metadata.getAlgorithm(), metadata.getBlockMode(), metadata.getPadding());
            log("Creating %s cipher…", cipherName);
            var cipher = Cipher.getInstance(cipherName, provider);
            log("Initializing cipher…");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(metadata.getInitializationVector()));
            log("Decrypting file…");
            try (var outputStream = new CipherOutputStream(output == null ? System.out : Files.newOutputStream(output), cipher)) {
                try (var encryptedInput = tarInput.getInputStream(dataEntry)) {
                    encryptedInput.transferTo(outputStream);
                }
            } catch (InvalidCipherTextIOException e) {
                error("Failed to decrypt file!");
                errorHelp("Did you select the correct key?");
                return 1;
            }
            log("Done");
            return 0;
        }
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
        return 0;
    }

    public static void main(String... args) {
        int exitCode = new CommandLine(new FileCrypt()).execute(args);
        System.exit(exitCode);
    }
    private void error(String message, Object... parameters) {
        System.out.println(CommandLine.Help.Ansi.AUTO.string("@|red " + String.format(message, parameters) + "|@"));
    }

    private void errorHelp(String message, Object... parameters) {
        System.out.println(CommandLine.Help.Ansi.AUTO.string("@|yellow " + String.format(message, parameters) + "|@"));
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
            System.out.println(CommandLine.Help.Ansi.AUTO.string("@|faint " + String.format(message, parameters) + "|@"));
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

    private Cipher createCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
        var cipherName = String.format("%s/%s/%s", algorithm, blockMode, padding);
        log("Creating %s cipher…", cipherName);
        return Cipher.getInstance(cipherName, provider);
    }

    private TarArchiveEntry createEntryWithSize(String name, long size) {
        var entry = new TarArchiveEntry(name);
        entry.setSize(size);
        return entry;
    }
}
