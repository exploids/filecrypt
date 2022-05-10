package com.exploids.filecrypt;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class HexByteBufferConverterTest {
    @Test
    void decodesCorrectly() {
        var converter = new HexByteBufferConverter();
        assertArrayEquals(new byte[] { (byte) 0xBE, (byte) 0xEF }, converter.convert("Beef").array());
    }
}
