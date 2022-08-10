package com.exploids.filecrypt.serialization;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Serializes byte buffers to hex strings.
 *
 * @author Luca Selinski
 */
public class ByteBufferSerializer extends JsonSerializer<ByteBuffer> {
    /**
     * Method that can be called to ask implementation to serialize
     * values of type this serializer handles.
     *
     * @param bytes              the value to serialize; can <b>not</b> be null.
     * @param jsonGenerator      the generator used to output resulting Json content
     * @param serializerProvider the provider that can be used to get serializers for serializing Objects value contains, if any
     */
    @Override
    public void serialize(ByteBuffer bytes, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeString(Hex.toHexString(bytes.array()));
    }
}
