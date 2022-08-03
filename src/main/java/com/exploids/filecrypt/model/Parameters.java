package com.exploids.filecrypt.model;

import picocli.CommandLine;

import java.nio.file.Path;

public class Parameters {
    @CommandLine.Option(names = {"-f", "--file"})
    private Path file;

    @CommandLine.Option(names = {"-o", "--output"}, arity = "0..1")
    private Path[] output;

    @CommandLine.Option(names = {"--key-file"})
    private Path keyFile;

    @CommandLine.Option(names = {"--metadata"})
    private Path metadataFile;

    @CommandLine.ArgGroup(exclusive = false)
    private Metadata metadata;

    @CommandLine.ArgGroup(exclusive = false)
    private KeyData keyData = new KeyData();

    @CommandLine.Option(names = {"-p", "--password"}, interactive = true)
    private char[] password;

    public Path getFile() {
        return file;
    }

    public void setFile(Path file) {
        this.file = file;
    }

    public Path[] getOutput() {
        return output;
    }

    public void setOutput(Path[] output) {
        this.output = output;
    }

    public Path getKeyFile() {
        return keyFile;
    }

    public void setKeyFile(Path keyFile) {
        this.keyFile = keyFile;
    }

    public Path getMetadataFile() {
        return metadataFile;
    }

    public void setMetadataFile(Path metadataFile) {
        this.metadataFile = metadataFile;
    }

    public Metadata getMetadata() {
        return metadata;
    }

    public void setMetadata(Metadata metadata) {
        this.metadata = metadata;
    }

    public char[] getPassword() {
        return password;
    }

    public void setPassword(char[] password) {
        this.password = password;
    }

    public KeyData getKeyData() {
        return keyData;
    }

    public void setKeyData(KeyData keyData) {
        this.keyData = keyData;
    }
}
