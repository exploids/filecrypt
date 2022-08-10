package com.exploids.filecrypt;

import picocli.CommandLine;

import java.nio.file.FileSystem;
import java.nio.file.Path;

public class CustomPathTypeConverter implements CommandLine.ITypeConverter<Path> {
    private final FileSystem fileSystem;

    public CustomPathTypeConverter(FileSystem fileSystem) {
        this.fileSystem = fileSystem;
    }

    @Override
    public Path convert(String value) {
        return fileSystem.getPath(value);
    }
}
