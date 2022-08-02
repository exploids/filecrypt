package com.exploids.filecrypt;

import com.exploids.filecrypt.serialization.HexByteBufferConverter;
import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import org.apache.commons.io.output.NullOutputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class FileCryptTest {
    private FileSystem fileSystem;
    private FileCrypt fileCrypt;
    private CommandLine commandLine;

    @BeforeEach
    void init() {
        fileSystem = Jimfs.newFileSystem(Configuration.unix());
        fileCrypt = new FileCrypt();
        commandLine = new CommandLine(fileCrypt)
                // .setOut(new PrintWriter(NullOutputStream.NULL_OUTPUT_STREAM))
                // .setErr(new PrintWriter(NullOutputStream.NULL_OUTPUT_STREAM))
                .registerConverter(ByteBuffer.class, new HexByteBufferConverter())
                .registerConverter(Path.class, new CustomPathTypeConverter(fileSystem));
    }

    @Test
    public void test() {
        assertEquals(3, 1 + 2);
    }

    @Test
    public void testHelp() {
        assertEquals(0, commandLine.execute("--help"));
    }

    @Test
    public void testEncryptionOk() throws IOException {
        Files.writeString(fileSystem.getPath("hello.txt"), "hello world");
        assertEquals(ExitCode.OK.getCode(), commandLine.execute("-f=hello.txt"));
        assertTrue(Files.exists(fileSystem.getPath("hello_enc")));
        assertTrue(Files.exists(fileSystem.getPath("hello_enc_key.txt")));
        assertTrue(Files.exists(fileSystem.getPath("hello_enc_meta.yaml")));
    }

    @Test
    public void testEncryptionMissingInput() {
        assertEquals(ExitCode.NO_SUCH_FILE.getCode(), commandLine.execute("-f=hello.txt"));
    }

    @Test
    public void createCipherCorrect() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        var cipher = fileCrypt.createCipher(new Metadata(Algorithm.AES, BlockMode.CBC, Padding.PKCS7, null));
        assertEquals("AES/CBC/PKCS7Padding", cipher.getAlgorithm());
    }
}
