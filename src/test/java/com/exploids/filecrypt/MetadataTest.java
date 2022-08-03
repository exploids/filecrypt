package com.exploids.filecrypt;

import com.exploids.filecrypt.model.Algorithm;
import com.exploids.filecrypt.model.BlockMode;
import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Padding;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class MetadataTest {
    @Test
    void nonNullValueIsSet() {
        var a = new Metadata(null, null, null, null);
        a.setFrom(new Metadata(Algorithm.AES, BlockMode.CBC, Padding.PKCS7, ByteBuffer.allocate(0)));
        assertEquals(Algorithm.AES, a.getCipherAlgorithm());
        assertEquals(BlockMode.CBC, a.getBlockMode());
        assertEquals(Padding.PKCS7, a.getPadding());
        assertNotNull(a.getInitializationVector());
    }

    @Test
    void nullValueIsNotSet() {
        var a = new Metadata(null, BlockMode.CBC, null, null);
        a.setFrom(new Metadata(null, null, null, null));
        assertEquals(BlockMode.CBC, a.getBlockMode());
    }
}
