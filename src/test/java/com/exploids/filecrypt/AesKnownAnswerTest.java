package com.exploids.filecrypt;

import org.apache.commons.io.input.CloseShieldInputStream;
import org.bouncycastle.util.encoders.Hex;
import org.ini4j.Ini;
import org.ini4j.Profile;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.Cipher;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class AesKnownAnswerTest {
    private static Stream<TestParameters> loadParameters() throws IOException {
        var entries = new ArrayList<TestParameters>();
        try (var in = new ZipInputStream(Objects.requireNonNull(AesKnownAnswerTest.class.getResourceAsStream("KAT_AES.zip")))) {
            ZipEntry entry;
            while ((entry = in.getNextEntry()) != null) {
                if (entry.getName().endsWith(".rsp")) {
                    var blockMode = entry.getName().substring(0, 3);
                    var ini = new Ini(CloseShieldInputStream.wrap(in));
                    readValues(ini.get("ENCRYPT"), false, entry.getName(), blockMode, entries);
                    readValues(ini.get("DECRYPT"), true, entry.getName(), blockMode, entries);
                } else {
                    System.out.printf("skipping entry %s%n", entry.getName());
                }
                in.closeEntry();
            }
        }
        return entries.stream();
    }

    private static void readValues(Profile.Section section, boolean decrypt, String name, String blockMode, List<TestParameters> entries) {
        var length = section.getAll("COUNT", int[].class).length;
        for (var index = 0; index < length; index++) {
            try {
                var count = section.get("COUNT", index, int.class);
                if (count != index) {
                    throw new RuntimeException("count mismatch");
                }
                var key = Hex.decode(section.get("KEY", index, String.class));
                byte[] iv = null;
                byte[] plainText = hex(section, index, "PLAINTEXT");
                byte[] cipherText = hex(section, index, "CIPHERTEXT");
                BlockMode blockModeValue = BlockMode.valueOf(blockMode);
                if (blockModeValue != BlockMode.ECB) {
                    iv = hex(section, index, "IV");
                }
                entries.add(new TestParameters(blockModeValue, decrypt, key, iv, plainText, cipherText));
            } catch (Exception e) {
                throw new RuntimeException(String.format("could not handle entry %s row %s", name, index), e);
            }
        }
    }

    private static byte[] hex(Profile.Section section, int index, String key) {
        var hex = section.get(key, index, String.class);
        return Hex.decode(hex.length() % 2 == 0 ? hex : "0" + hex);
    }

    @ParameterizedTest
    @MethodSource("loadParameters")
    public void test(TestParameters parameters) {

    }

    private record TestParameters(BlockMode blockMode, boolean decrypt, byte[] key, byte[] iv, byte[] plainText, byte[] cipherText) {
    }
}
