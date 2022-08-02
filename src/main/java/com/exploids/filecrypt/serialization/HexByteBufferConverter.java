package com.exploids.filecrypt.serialization;

import org.bouncycastle.util.encoders.Hex;
import picocli.CommandLine;

import java.nio.ByteBuffer;

public class HexByteBufferConverter implements CommandLine.ITypeConverter<ByteBuffer> {
    @Override
    public ByteBuffer convert(String value) {
        return ByteBuffer.wrap(Hex.decode(value));
    }
}
