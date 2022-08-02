package com.exploids.filecrypt;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

public class AesKnownAnswerTest {
    private static Stream<TestParameters> loadParameters() {
        return Stream.of(new TestParameters(new byte[] {}, new byte[] {}, new byte[] {}));
    }

    @ParameterizedTest
    @MethodSource("loadParameters")
    public void test(TestParameters parameters) {

    }

    private record TestParameters(byte[] key, byte[] plainText, byte[] cipherText) {
    }
}
