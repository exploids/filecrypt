package com.exploids.filecrypt.serialization;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.nio.ByteBuffer;

public class ByteBufferDeserializer extends JsonDeserializer<ByteBuffer> {
    @Override
    public ByteBuffer deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JacksonException {
        return ByteBuffer.wrap(Hex.decode(jsonParser.readValueAs(String.class)));
    }
}
