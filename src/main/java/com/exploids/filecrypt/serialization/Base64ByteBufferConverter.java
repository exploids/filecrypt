package com.exploids.filecrypt.serialization;

import org.bouncycastle.util.encoders.Base64;
import picocli.CommandLine;

import java.nio.ByteBuffer;

/**
 * Converts command line arguments from base64 strings to byte buffers.
 *
 * @author Luca Selinski
 */
public class Base64ByteBufferConverter implements CommandLine.ITypeConverter<ByteBuffer> {
    /**
     * Converts the specified command line argument value to some domain object.
     *
     * @param value the command line argument String value
     * @return the resulting domain object
     */
    @Override
    public ByteBuffer convert(String value) {
        return ByteBuffer.wrap(Base64.decode(value));
    }
}
