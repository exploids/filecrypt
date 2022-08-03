package com.exploids.filecrypt.serialization;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.nio.ByteBuffer;

public class ByteBufferSerializer extends JsonSerializer<ByteBuffer> {
    @Override
    public void serialize(ByteBuffer bytes, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeString(Hex.toHexString(bytes.array()));
    }
}
