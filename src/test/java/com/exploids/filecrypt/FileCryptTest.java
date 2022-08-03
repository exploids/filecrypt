package com.exploids.filecrypt;

import com.exploids.filecrypt.model.Algorithm;
import com.exploids.filecrypt.model.BlockMode;
import com.exploids.filecrypt.model.ExitCode;
import com.exploids.filecrypt.model.Metadata;
import com.exploids.filecrypt.model.Padding;
import com.exploids.filecrypt.serialization.HexByteBufferConverter;
import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
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
        assertEquals(ExitCode.FAILURE.getCode(), commandLine.execute("--file=hello.txt", "--padding=NO"));
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
    public void testMacOk() throws IOException {
        Files.writeString(fileSystem.getPath("hello.txt"), "hello world");
        assertEquals(ExitCode.OK.getCode(), commandLine.execute("--file=hello.txt", "--mac"));
        assertTrue(Files.readString(fileSystem.getPath("hello_encrypted_meta.yaml")).contains("mac: "));
        System.out.println(Hex.toHexString(Files.readAllBytes(fileSystem.getPath("hello_encrypted"))));
        System.out.println(Files.readString(fileSystem.getPath("hello_encrypted_key.yaml")));
        System.out.println(Files.readString(fileSystem.getPath("hello_encrypted_meta.yaml")));
    }

    @Test
    public void testEncryptMacAESCMAC() throws IOException {
        Files.writeString(fileSystem.getPath("hello.txt"), "hello world");
        assertEquals(ExitCode.OK.getCode(), commandLine.execute("--file=hello.txt", "--mac", "--mac-algorithm=AESCMAC"));
        assertTrue(Files.readString(fileSystem.getPath("hello_encrypted_meta.yaml")).contains("mac algorithm: AESCMAC"));
        System.out.println(Hex.toHexString(Files.readAllBytes(fileSystem.getPath("hello_encrypted"))));
        System.out.println(Files.readString(fileSystem.getPath("hello_encrypted_key.yaml")));
        System.out.println(Files.readString(fileSystem.getPath("hello_encrypted_meta.yaml")));
    }

    @Test
    public void testDecryptValidMacHMACSHA256() throws IOException {
        Files.write(fileSystem.getPath("hello_encrypted"), Hex.decode("d6e9576cb3512d2016fb82f0308da49e"));
        assertEquals(ExitCode.OK.getCode(), commandLine.execute(
                "--decrypt",
                "--file=hello_encrypted",
                "--iv=abb04ba47918a17a54f831240a72275b",
                "--cipher-key=b7951dbdb94c35619b91a614b58be07c355a5e5d3cb22b43",
                "--mac=80cb3bd1e1746b884be36fbd225f4d03a1324ebe0b97ad50082dd7889c653481",
                "--mac-algorithm=HMACSHA256",
                "--mac-key=eaf7831056238086b059b3a4f92a1543f496aec1cee9ec5e555108b68c8c441d"));
    }

    @Test
    public void testDecryptWrongMacKeyHMACSHA256() throws IOException {
        Files.write(fileSystem.getPath("hello_encrypted"), Hex.decode("d6e9576cb3512d2016fb82f0308da49e"));
        assertEquals(ExitCode.MAC_VERIFICATION_FAILED.getCode(), commandLine.execute(
                "--decrypt",
                "--file=hello_encrypted",
                "--iv=abb04ba47918a17a54f831240a72275b",
                "--cipher-key=b7951dbdb94c35619b91a614b58be07c355a5e5d3cb22b43",
                "--mac=80cb3bd1e1746b884be36fbd225f4d03a1324ebe0b97ad50082dd7889c653481",
                "--mac-algorithm=HMACSHA256",
                "--mac-key=b466146857f8158e37e263d3764488010c0d56e12a22c5c14ebdea3d891dbee5"));
    }

    @Test
    public void testDecryptMissingMacKeyHMACSHA256() throws IOException {
        Files.write(fileSystem.getPath("hello_encrypted"), Hex.decode("d6e9576cb3512d2016fb82f0308da49e"));
        assertEquals(ExitCode.MAC_VERIFICATION_FAILED.getCode(), commandLine.execute(
                "--decrypt",
                "--file=hello_encrypted",
                "--iv=abb04ba47918a17a54f831240a72275b",
                "--cipher-key=b7951dbdb94c35619b91a614b58be07c355a5e5d3cb22b43",
                "--mac=80cb3bd1e1746b884be36fbd225f4d03a1324ebe0b97ad50082dd7889c653481",
                "--mac-algorithm=HMACSHA256"));
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
