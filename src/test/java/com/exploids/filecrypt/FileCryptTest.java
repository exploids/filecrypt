package com.exploids.filecrypt;

import com.exploids.filecrypt.model.*;
import com.exploids.filecrypt.serialization.HexByteBufferConverter;
import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import org.apache.commons.io.output.NullOutputStream;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
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
                 .setOut(new PrintWriter(NullOutputStream.NULL_OUTPUT_STREAM))
                // .setErr(new PrintWriter(NullOutputStream.NULL_OUTPUT_STREAM))
                .registerConverter(ByteBuffer.class, new HexByteBufferConverter())
                .registerConverter(Path.class, new CustomPathTypeConverter(fileSystem));
    }

    @Test
    public void testHelp() {
        assertEquals(0, commandLine.execute("--help"));
    }

    @Test
    public void testZeroBytePaddingInsecure() throws IOException {
        Files.writeString(fileSystem.getPath("hello.txt"), "hello world");
        assertEquals(ExitCode.INSECURE.getCode(), commandLine.execute("--file=hello.txt", "--padding=ZERO_BYTE"));
    }

    @Test
    public void testInsecureAllowed() throws IOException {
        Files.writeString(fileSystem.getPath("hello.txt"), "hello world");
        assertEquals(ExitCode.OK.getCode(), commandLine.execute("--file=hello.txt", "--padding=ZERO_BYTE", "--insecure"));
    }

    @Test
    public void testNoPaddingFail() throws IOException {
        Files.writeString(fileSystem.getPath("hello.txt"), "hello world");
        assertEquals(ExitCode.FAILURE.getCode(), commandLine.execute("--file=hello.txt", "--padding=NONE"));
    }

    @Test
    public void testAesWrongKeySizeFail() throws IOException {
        Files.writeString(fileSystem.getPath("hello.txt"), "hello world");
        assertEquals(ExitCode.KEY_ERROR.getCode(), commandLine.execute("--file=hello.txt", "--algorithm=AES", "--key-size=168"));
    }

    @Test
    public void testEncryptionOk() throws IOException {
        Files.writeString(fileSystem.getPath("hello.txt"), "hello world");
        assertEquals(ExitCode.OK.getCode(), commandLine.execute("--file=hello.txt"));
        assertTrue(Files.exists(fileSystem.getPath("hello_encrypted")));
        assertTrue(Files.exists(fileSystem.getPath("hello_encrypted_key.yaml")));
        assertTrue(Files.exists(fileSystem.getPath("hello_encrypted_meta.yaml")));
        // System.out.println(Hex.toHexString(Files.readAllBytes(fileSystem.getPath("hello_encrypted"))));
        // System.out.println(Files.readString(fileSystem.getPath("hello_encrypted_key.yaml")));
        // System.out.println(Files.readString(fileSystem.getPath("hello_encrypted_meta.yaml")));
    }

    @ParameterizedTest
    @EnumSource(Algorithm.class)
    public void testEncryptionAlgorithms(Algorithm algorithm) throws IOException {
        Files.writeString(fileSystem.getPath("hello.txt"), "hello world");
        assertEquals(ExitCode.OK.getCode(), commandLine.execute("--file=hello.txt", "--algorithm", algorithm.toString(), "--insecure"));
        assertTrue(Files.exists(fileSystem.getPath("hello_encrypted")));
        assertTrue(Files.exists(fileSystem.getPath("hello_encrypted_key.yaml")));
        assertTrue(Files.readString(fileSystem.getPath("hello_encrypted_meta.yaml")).contains("algorithm: " + algorithm));
        assertEquals(ExitCode.OK.getCode(), commandLine.execute("--decrypt", "--file=hello_encrypted"));
        assertEquals("hello world", Files.readString(fileSystem.getPath("hello_encrypted_decrypted")));
    }

    @ParameterizedTest
    @EnumSource(BlockMode.class)
    public void testEncryptionBlockModes(BlockMode blockMode) throws IOException {
        Files.writeString(fileSystem.getPath("hello.txt"), "hello world");
        assertEquals(ExitCode.OK.getCode(), commandLine.execute("--file=hello.txt", "--block-mode", blockMode.toString(), "--insecure"));
        assertTrue(Files.exists(fileSystem.getPath("hello_encrypted")));
        assertTrue(Files.exists(fileSystem.getPath("hello_encrypted_key.yaml")));
        assertTrue(Files.readString(fileSystem.getPath("hello_encrypted_meta.yaml")).contains("block mode: " + blockMode));
        assertEquals(ExitCode.OK.getCode(), commandLine.execute("--decrypt", "--file=hello_encrypted"));
        assertEquals("hello world", Files.readString(fileSystem.getPath("hello_encrypted_decrypted")));
    }

    @ParameterizedTest
    @EnumSource(Padding.class)
    public void testEncryptionPaddings(Padding padding) throws IOException {
        Files.write(fileSystem.getPath("hello.txt"), new byte[128]);
        assertEquals(ExitCode.OK.getCode(), commandLine.execute("--file=hello.txt", "--padding", padding.toString(), "--insecure"));
        assertTrue(Files.exists(fileSystem.getPath("hello_encrypted")));
        assertTrue(Files.exists(fileSystem.getPath("hello_encrypted_key.yaml")));
        assertTrue(Files.readString(fileSystem.getPath("hello_encrypted_meta.yaml")).contains("padding: " + padding));
        assertEquals(ExitCode.OK.getCode(), commandLine.execute("--decrypt", "--file=hello_encrypted"));
        assertArrayEquals(new byte[128], Files.readAllBytes(fileSystem.getPath("hello_encrypted_decrypted")));
    }

    @ParameterizedTest
    @EnumSource(PasswordAlgorithm.class)
    public void testPasswordAlgorithm(PasswordAlgorithm passwordAlgorithm) throws IOException {
        Files.writeString(fileSystem.getPath("hello.txt"), "hello world");
        assertEquals(ExitCode.OK.getCode(), commandLine.execute("--file=hello.txt", "--password=123456", "--password-algorithm", passwordAlgorithm.toString()));
        System.out.println(Hex.toHexString(Files.readAllBytes(fileSystem.getPath("hello_encrypted"))));
        System.out.println(Files.readString(fileSystem.getPath("hello_encrypted_key.yaml")));
        System.out.println(Files.readString(fileSystem.getPath("hello_encrypted_meta.yaml")));
        assertTrue(Files.exists(fileSystem.getPath("hello_encrypted")));
        assertTrue(Files.exists(fileSystem.getPath("hello_encrypted_key.yaml")));
        assertTrue(Files.readString(fileSystem.getPath("hello_encrypted_meta.yaml")).contains("password algorithm: " + passwordAlgorithm));
        assertEquals(ExitCode.OK.getCode(), commandLine.execute("--decrypt", "--file=hello_encrypted", "--password=123456"));
        assertEquals("hello world", Files.readString(fileSystem.getPath("hello_encrypted_decrypted")));
    }

    @Test
    public void testDecryptionOk() throws IOException {
        Files.write(fileSystem.getPath("hello_encrypted"), Hex.decode("0026a5d57ce907234d91ddc8a2f8a6a7"));
        assertEquals(ExitCode.OK.getCode(), commandLine.execute(
                "--decrypt",
                "--file=hello_encrypted",
                "--cipher-key=f17cc514a9d2570924ec680414951fb33051603b1940f06a",
                "--iv=ad4b3a44f3cad4b4b2657b7cf71fd3f1"));
        assertEquals("hello world", Files.readString(fileSystem.getPath("hello_encrypted_decrypted")));
    }

    @Test
    public void testEncryptMacOk() throws IOException {
        Files.writeString(fileSystem.getPath("hello.txt"), "hello world");
        assertEquals(ExitCode.OK.getCode(), commandLine.execute("--file=hello.txt", "--verification"));
        assertTrue(Files.readString(fileSystem.getPath("hello_encrypted_meta.yaml")).contains("verification: "));
    }

    @Test
    public void testEncryptMacAESCMAC() throws IOException {
        Files.writeString(fileSystem.getPath("hello.txt"), "hello world");
        assertEquals(ExitCode.OK.getCode(), commandLine.execute("--file=hello.txt", "--verification", "--verification-algorithm=AESCMAC"));
        assertTrue(Files.readString(fileSystem.getPath("hello_encrypted_meta.yaml")).contains("verification algorithm: AESCMAC"));
    }

    @Test
    public void testDecryptValidMacHMACSHA256() throws IOException {
        Files.write(fileSystem.getPath("hello_encrypted"), Hex.decode("d6e9576cb3512d2016fb82f0308da49e"));
        assertEquals(ExitCode.OK.getCode(), commandLine.execute(
                "--decrypt",
                "--file=hello_encrypted",
                "--iv=abb04ba47918a17a54f831240a72275b",
                "--cipher-key=b7951dbdb94c35619b91a614b58be07c355a5e5d3cb22b43",
                "--verification=80cb3bd1e1746b884be36fbd225f4d03a1324ebe0b97ad50082dd7889c653481",
                "--verification-algorithm=HMACSHA256",
                "--verification-key=eaf7831056238086b059b3a4f92a1543f496aec1cee9ec5e555108b68c8c441d"));
    }

    @Test
    public void testDecryptWrongMacKeyHMACSHA256() throws IOException {
        Files.write(fileSystem.getPath("hello_encrypted"), Hex.decode("d6e9576cb3512d2016fb82f0308da49e"));
        assertEquals(ExitCode.VERIFICATION_FAILED.getCode(), commandLine.execute(
                "--decrypt",
                "--file=hello_encrypted",
                "--iv=abb04ba47918a17a54f831240a72275b",
                "--cipher-key=b7951dbdb94c35619b91a614b58be07c355a5e5d3cb22b43",
                "--verification=80cb3bd1e1746b884be36fbd225f4d03a1324ebe0b97ad50082dd7889c653481",
                "--verification-algorithm=HMACSHA256",
                "--verification-key=b466146857f8158e37e263d3764488010c0d56e12a22c5c14ebdea3d891dbee5"));
    }

    @Test
    public void testDecryptMissingMacKeyHMACSHA256() throws IOException {
        Files.write(fileSystem.getPath("hello_encrypted"), Hex.decode("d6e9576cb3512d2016fb82f0308da49e"));
        assertEquals(ExitCode.VERIFICATION_FAILED.getCode(), commandLine.execute(
                "--decrypt",
                "--file=hello_encrypted",
                "--iv=abb04ba47918a17a54f831240a72275b",
                "--cipher-key=b7951dbdb94c35619b91a614b58be07c355a5e5d3cb22b43",
                "--verification=80cb3bd1e1746b884be36fbd225f4d03a1324ebe0b97ad50082dd7889c653481",
                "--verification-algorithm=HMACSHA256"));
    }

    @Test
    public void testEncryptHashSHA256() throws IOException {
        Files.writeString(fileSystem.getPath("hello.txt"), "hello world");
        assertEquals(ExitCode.OK.getCode(), commandLine.execute("--file=hello.txt", "--verification", "--verification-algorithm=SHA256"));
        assertTrue(Files.readString(fileSystem.getPath("hello_encrypted_meta.yaml")).contains("verification algorithm: SHA256"));
    }

    @Test
    public void testDecryptValidHashSHA256() throws IOException {
        Files.write(fileSystem.getPath("hello_encrypted"), Hex.decode("62d8ebc735ea27e1b9fd5b7fe3ea3129"));
        assertEquals(ExitCode.OK.getCode(), commandLine.execute(
                "--decrypt",
                "--file=hello_encrypted",
                "--iv=c1b0275ba3a39e55193c22faa20b0d94",
                "--cipher-key=dfa51c881060e549cff85167c3ad07a0c4bd561af5bace6a273ae11b0e560ed3",
                "--verification=9c703c23442e841cac723cfe06573cb7d94b4e872a14641d9d862eae6ff7a66b",
                "--verification-algorithm=SHA256"));
    }

    @Test
    public void testDecryptWrongHashSHA256() throws IOException {
        Files.write(fileSystem.getPath("hello_encrypted"), Hex.decode("62d8ebc735ea27e1b9fd5b7fe3ea3129"));
        assertEquals(ExitCode.VERIFICATION_FAILED.getCode(), commandLine.execute(
                "--decrypt",
                "--file=hello_encrypted",
                "--iv=c1b0275ba3a39e55193c22faa20b0d94",
                "--cipher-key=dfa51c881060e549cff85167c3ad07a0c4bd561af5bace6a273ae11b0e560ed3",
                "--verification=0d17a7d00e0459ddea3f0ab6ee42c7b19912d72ffc7566003dc5458532d8a1d6",
                "--verification-algorithm=SHA256"));
    }

    @Test
    public void testEncryptionMissingInput() {
        assertEquals(ExitCode.NO_SUCH_FILE.getCode(), commandLine.execute("--file=hello.txt"));
    }

    @Test
    public void createCipherCorrect() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        var cipher = fileCrypt.createCipher(new Metadata(Algorithm.AES, BlockMode.CBC, Padding.PKCS7, null));
        assertEquals("AES/CBC/PKCS7Padding", cipher.getAlgorithm());
    }
}
