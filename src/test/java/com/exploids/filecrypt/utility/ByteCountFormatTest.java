package com.exploids.filecrypt.utility;

import com.exploids.filecrypt.utility.ByteCountFormat;
import org.junit.jupiter.api.Test;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author Luca Selinski
 */
public class ByteCountFormatTest {
    private final ByteCountFormat format = new ByteCountFormat(Locale.GERMANY);

    @Test
    void test0() {
        assertEquals("0 B", format.format(0));
    }

    @Test
    void test1kB() {
        assertEquals("1 kB", format.format(1_000));
    }

    @Test
    void test1MB() {
        assertEquals("1 MB", format.format(1_000_000));
    }

    @Test
    void test1GB() {
        assertEquals("1 GB", format.format(1_000_000_000));
    }

    @Test
    void test1TB() {
        assertEquals("1 TB", format.format(1_000_000_000_000L));
    }

    @Test
    void testMinus1TB() {
        assertEquals("-1 TB", format.format(-1_000_000_000_000L));
    }

    @Test
    void test1PB() {
        assertEquals("1 PB", format.format(1_000_000_000_000_000L));
    }

    @Test
    void test1EB() {
        assertEquals("1 EB", format.format(1_000_000_000_000_000_000L));
    }

    @Test
    void testMax() {
        assertEquals("9,2 EB", format.format(Long.MAX_VALUE));
    }

    @Test
    void testMin() {
        assertEquals("-9,2 EB", format.format(Long.MIN_VALUE));
    }

    @Test
    void test999B() {
        assertEquals("999 B", format.format(999));
    }

    @Test
    void test1049B() {
        assertEquals("1 kB", format.format(1_049));
    }

    @Test
    void test1050B() {
        assertEquals("1,1 kB", format.format(1_050));
    }
}
