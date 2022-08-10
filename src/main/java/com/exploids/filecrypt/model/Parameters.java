package com.exploids.filecrypt.model;

import com.exploids.filecrypt.serialization.Base64ByteBufferConverter;
import picocli.CommandLine;

import java.nio.ByteBuffer;
import java.nio.file.Path;

/**
 * The model for all parameters used by filecrypt.
 * This does not include parameters specific to the CLI.
 *
 * @author Luca Selinski
 */
public class Parameters {
    /**
     * The input file path.
     */
    @CommandLine.Parameters(index = "0", arity = "1", descriptionKey = "file")
    private Path file;

    /**
     * The output file path.
     */
    @CommandLine.Parameters(index = "1", arity = "0..1", descriptionKey = "output")
    private Path output;

    /**
     * The key file path.
     */
    @CommandLine.Option(names = {"--key-file"})
    private Path keyFile;

    /**
     * The metadata file path.
     */
    @CommandLine.Option(names = {"--metadata"})
    private Path metadataFile;

    /**
     * The metadata directly given via the command line arguments.
     */
    @CommandLine.ArgGroup(validate = false)
    private Metadata metadata;

    /**
     * The keys directly given via the command line arguments.
     */
    @CommandLine.ArgGroup(validate = false)
    private KeyData keyData = new KeyData();

    /**
     * The password.
     */
    @CommandLine.Option(names = {"-p", "--password"}, interactive = true)
    private char[] password;

    /**
     * The private key for the signature.
     */
    @CommandLine.Option(names = {"--signature-private-key"}, converter = Base64ByteBufferConverter.class)
    private ByteBuffer signaturePrivateKey;

    /**
     * Whether the user explicitly allows insecure encryption and decryption.
     */
    @CommandLine.Option(names = {"--insecure"})
    private boolean insecureAllowed;

    /**
     * Gets the input file path.
     *
     * @return the input file path
     */
    public Path getFile() {
        return file;
    }

    /**
     * Sets the input file path.
     *
     * @param file the input file path
     */
    public void setFile(Path file) {
        this.file = file;
    }

    /**
     * Gets the output file path.
     *
     * @return the output file path
     */
    public Path getOutput() {
        return output;
    }

    /**
     * Sets the output file path
     *
     * @param output the output file path
     */
    public void setOutput(Path output) {
        this.output = output;
    }

    /**
     * Gets the key file path.
     *
     * @return the key file path
     */
    public Path getKeyFile() {
        return keyFile;
    }

    /**
     * Sets the key file path.
     *
     * @param keyFile the key file path
     */
    public void setKeyFile(Path keyFile) {
        this.keyFile = keyFile;
    }

    /**
     * Gets the metadata file path.
     *
     * @return the metadata file path
     */
    public Path getMetadataFile() {
        return metadataFile;
    }

    /**
     * Sets the metadata file path.
     *
     * @param metadataFile the metadata file path
     */
    public void setMetadataFile(Path metadataFile) {
        this.metadataFile = metadataFile;
    }

    /**
     * Gets the metadata directly given via the command line arguments.
     *
     * @return the metadata
     */
    public Metadata getMetadata() {
        return metadata;
    }

    /**
     * Sets the metadata directly given via the command line arguments.
     *
     * @param metadata the metadata
     */
    public void setMetadata(Metadata metadata) {
        this.metadata = metadata;
    }

    /**
     * Gets the keys directly given via the command line arguments.
     *
     * @return the keys
     */
    public KeyData getKeyData() {
        return keyData;
    }

    /**
     * Sets the keys directly given via the command line arguments.
     *
     * @param keyData the keys
     */
    public void setKeyData(KeyData keyData) {
        this.keyData = keyData;
    }

    /**
     * Gets the password.
     *
     * @return the password
     */
    public char[] getPassword() {
        return password;
    }

    /**
     * Sets the password.
     *
     * @param password the password
     */
    public void setPassword(char[] password) {
        this.password = password;
    }

    /**
     * Gets the private key for the signature.
     *
     * @return the private key for the signature
     */
    public ByteBuffer getSignaturePrivateKey() {
        return signaturePrivateKey;
    }

    /**
     * Sets the private key for the signature.
     *
     * @param signaturePrivateKey the private key for the signature
     */
    public void setSignaturePrivateKey(ByteBuffer signaturePrivateKey) {
        this.signaturePrivateKey = signaturePrivateKey;
    }

    /**
     * Gets whether the user explicitly allows insecure encryption and decryption.
     *
     * @return whether the user explicitly allows insecure encryption and decryption
     */
    public boolean isInsecureAllowed() {
        return insecureAllowed;
    }

    /**
     * Sets whether the user explicitly allows insecure encryption and decryption.
     *
     * @param insecureAllowed whether the user explicitly allows insecure encryption and decryption
     */
    public void setInsecureAllowed(boolean insecureAllowed) {
        this.insecureAllowed = insecureAllowed;
    }
}
