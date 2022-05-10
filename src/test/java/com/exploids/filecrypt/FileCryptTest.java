package com.exploids.filecrypt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class FileCryptTest {
    private FileCrypt fileCrypt;

    @BeforeEach
    void init() {
        fileCrypt = new FileCrypt();
    }

    @Test
    public void test() {
        assertEquals(3, 1 + 2);
    }

    @Test
    public void createCipherCorrect() throws NoSuchPaddingException, NoSuchAlgorithmException {
        var cipher = fileCrypt.createCipher(new Metadata(Algorithm.AES, BlockMode.CBC, Padding.PKCS7, null));
        assertEquals("AES/CBC/PKCS7Padding", cipher.getAlgorithm());
    }
}
