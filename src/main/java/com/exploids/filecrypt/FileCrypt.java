package com.exploids.filecrypt;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;
import java.security.Provider;
import java.security.Security;
import java.util.concurrent.Callable;

/**
 * @author Luca Selinski
 */
@Command(name = "filecrypt", mixinStandardHelpOptions = true, version = "1.0.0", description = "Encrypts or decrypts a file.")
class FileCrypt implements Callable<Integer> {
    public FileCrypt() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Option(names = {"-m", "--metadata"}, description = "The file to use for metadata.")
    private File metadata;

    @Option(names = {"-a", "--algorithm"}, description = "MD5, SHA-1, SHA-256, ...")
    private String algorithm = "SHA-256";

    @Option(names = {"-p", "--password"}, description = "The password to use.", interactive = true)
    private char[] password;

    @Option(names = {"-d", "--padding"}, description = "The padding to use: ${COMPLETION-CANDIDATES}. (Default: ${DEFAULT-VALUE})")
    private Padding padding = Padding.NO;

    @Command(name = "encrypt", aliases = {"e"})
    public Integer encrypt(
            @Parameters(index = "0", description = "The file to use.") File file
    ) {
        System.out.println("Encrypt.");
        return 0;
    }

    @Command(name = "decrypt", aliases = {"d"})
    public Integer decrypt(
            @Parameters(index = "0", description = "The file to use.") File file
    ) {
        System.out.printf("Decrypt %s%n", file.getAbsolutePath());
        return 0;
    }

    @Override
    public Integer call() {
        listProviders();
        return 0;
    }

    public static void main(String... args) {
        int exitCode = new CommandLine(new FileCrypt()).execute(args);
        System.exit(exitCode);
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
}
