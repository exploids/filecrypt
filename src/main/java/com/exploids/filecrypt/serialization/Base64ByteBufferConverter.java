package com.exploids.filecrypt.serialization;

import org.bouncycastle.util.encoders.Base64;
import picocli.CommandLine;

import java.nio.ByteBuffer;

/**
 * @author Luca Selinski
 */
public class Base64ByteBufferConverter implements CommandLine.ITypeConverter<ByteBuffer> {
    @Override
    public ByteBuffer convert(String value) {
        return ByteBuffer.wrap(Base64.decode(value));
    }
}
