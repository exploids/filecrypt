package com.exploids.filecrypt.utility;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Transfers data from an input stream to an output stream.
 *
 * @author Luca Selinski
 */
public class DataTransfer {
    /**
     * The logger for this class.
     */
    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * The formatter to use for byte counts.
     */
    private final ByteCountFormat byteFormat = new ByteCountFormat();

    /**
     * Transfers all the data.
     *
     * @param in   the input stream
     * @param out  the output stream
     * @param size the expected amount of data
     * @throws IOException if some I/O error occurs
     */
    public void transferData(InputStream in, OutputStream out, long size) throws IOException {
        long transferred = 0;
        byte[] buffer = new byte[IOUtils.DEFAULT_BUFFER_SIZE];
        int read;
        var lastUpdate = System.currentTimeMillis();
        boolean didGiveProgress = false;
        while ((read = in.read(buffer)) >= 0) {
            out.write(buffer, 0, read);
            transferred += read;
            if (System.currentTimeMillis() - lastUpdate >= 5000) {
                lastUpdate += 5000;
                logger.info("Processed {} ({}%)", byteFormat.format(transferred), (int) ((double) transferred / size * 100));
                didGiveProgress = true;
            }
        }
        if (didGiveProgress) {
            logger.info("Processed {} (100%)", byteFormat.format(transferred));
        }
    }
}
