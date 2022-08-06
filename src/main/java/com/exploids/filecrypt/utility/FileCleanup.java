package com.exploids.filecrypt.utility;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.util.Stack;

/**
 * @author Luca Selinski
 */
public class FileCleanup implements AutoCloseable {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final Stack<Path> toDelete = new Stack<>();

    public OutputStream newOutputStream(Path path, OpenOption... openOptions) throws IOException {
        var outputStream = Files.newOutputStream(path, openOptions);
        toDelete.push(path);
        return outputStream;
    }

    public BufferedWriter newBufferedWriter(Path path, OpenOption... openOptions) throws IOException {
        var writer = Files.newBufferedWriter(path, openOptions);
        toDelete.push(path);
        return writer;
    }

    public void commit() {
        toDelete.clear();
        logger.debug("The cleanup stack has been cleared.");
    }

    @Override
    public void close() {
        while (!toDelete.empty()) {
            var path = toDelete.pop();
            try {
                Files.delete(path);
                logger.debug("Cleaned up {}.", path);
            } catch (IOException e) {
                logger.warn("Tried to clean up {}, but an error occurred.", path, e);
            }
        }
    }
}
