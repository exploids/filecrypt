package com.exploids.filecrypt.serialization;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Deserializes hex strings to byte buffers.
 *
 * @author Luca Selinski
 */
public class ByteBufferDeserializer extends JsonDeserializer<ByteBuffer> {
    /**
     * Method that can be called to ask implementation to deserialize
     * JSON content into the value type this serializer handles.
     * Returned instance is to be constructed by method itself.
     *
     * @param jsonParser             the parser used for reading JSON content
     * @param deserializationContext the context that can be used to access information about this deserialization activity
     * @return the deserialized value
     */
    @Override
    public ByteBuffer deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        return ByteBuffer.wrap(Hex.decode(jsonParser.readValueAs(String.class)));
    }
}
