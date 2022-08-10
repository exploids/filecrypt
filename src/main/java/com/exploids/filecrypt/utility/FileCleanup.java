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
 * Deletes newly created files in case of an error.
 *
 * @author Luca Selinski
 */
public class FileCleanup implements AutoCloseable {
    /**
     * The logger for this class.
     */
    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * A stack of all files to delete in case of an error.
     */
    private final Stack<Path> toDelete = new Stack<>();

    /**
     * A variant of {@link Files#newOutputStream(Path, OpenOption...)} that registers the new file to be cleaned up.
     *
     * @param path        the path to the file to open or create
     * @param openOptions options specifying how the file is opened
     * @return a new output stream
     * @throws IOException if an I/O error occurs
     */
    public OutputStream newOutputStream(Path path, OpenOption... openOptions) throws IOException {
        var outputStream = Files.newOutputStream(path, openOptions);
        toDelete.push(path);
        return outputStream;
    }

    /**
     * A variant of {@link Files#newBufferedWriter(Path, OpenOption...)} that registers the new file to be cleaned up.
     *
     * @param path        the path to the file to open or create
     * @param openOptions a new buffered writer, with default buffer size, to write text to the file
     * @return a new buffered writer, with default buffer size, to write text to the file
     * @throws IOException if an I/O error occurs
     */
    public BufferedWriter newBufferedWriter(Path path, OpenOption... openOptions) throws IOException {
        var writer = Files.newBufferedWriter(path, openOptions);
        toDelete.push(path);
        return writer;
    }

    /**
     * Commits the newly created files.
     * Files that have been committed won't be cleaned up.
     */
    public void commit() {
        toDelete.clear();
        logger.debug("The cleanup stack has been cleared.");
    }

    /**
     * Deletes all files that have not been committed.
     */
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
