package com.exploids.filecrypt.serialization;

import org.bouncycastle.util.encoders.Hex;
import picocli.CommandLine;

import java.nio.ByteBuffer;

/**
 * Converts command line arguments from hex strings to byte buffers.
 *
 * @author Luca Selinski
 */
public class HexByteBufferConverter implements CommandLine.ITypeConverter<ByteBuffer> {
    /**
     * Converts the specified command line argument value to some domain object.
     *
     * @param value the command line argument String value
     * @return the resulting domain object
     */
    @Override
    public ByteBuffer convert(String value) {
        return ByteBuffer.wrap(Hex.decode(value));
    }
}
