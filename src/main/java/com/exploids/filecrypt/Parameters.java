package com.exploids.filecrypt;

import picocli.CommandLine;

import java.nio.ByteBuffer;
import java.nio.file.Path;

public class Parameters {
    @CommandLine.Option(names = {"-f", "--file"})
    private Path file;

    @CommandLine.Option(names = {"-o", "--output"}, arity = "0..1")
    private Path[] output;

    @CommandLine.Option(names = {"--key"})
    private ByteBuffer key;

    @CommandLine.Option(names = {"--key-file"})
    private Path keyFile;

    @CommandLine.Option(names = {"--metadata"})
    private Path metadataFile;

    @CommandLine.ArgGroup(exclusive = false)
    private Metadata metadataArguments;

    @CommandLine.Option(names = {"-p", "--password"}, description = "The password to use.", interactive = true)
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

    public ByteBuffer getKey() {
        return key;
    }

    public void setKey(ByteBuffer key) {
        this.key = key;
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

    public Metadata getMetadataArguments() {
        return metadataArguments;
    }

    public void setMetadataArguments(Metadata metadataArguments) {
        this.metadataArguments = metadataArguments;
    }

    public char[] getPassword() {
        return password;
    }

    public void setPassword(char[] password) {
        this.password = password;
    }
}
