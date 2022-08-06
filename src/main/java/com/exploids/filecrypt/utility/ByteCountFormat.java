package com.exploids.filecrypt.utility;

import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.util.Locale;

/**
 * Formats byte counts as human-readable strings.
 *
 * @author Luca Selinski
 */
public class ByteCountFormat {
    /**
     * The units to display.
     */
    private final String[] units = new String[]{"B", "kB", "MB", "GB", "TB", "PB", "EB"};

    /**
     * The decimal formatter to use.
     */
    private final DecimalFormat decimalFormat;

    /**
     * Creates a new formatter using the default locale.
     */
    public ByteCountFormat() {
        this(Locale.getDefault());
    }

    /**
     * Creates a new formatter using the given locale.
     *
     * @param locale the locale to use
     */
    public ByteCountFormat(Locale locale) {
        decimalFormat = new DecimalFormat("#,##0.#", DecimalFormatSymbols.getInstance(locale));
    }

    /**
     * Formats a number of bytes.
     *
     * @param byteCount the number of bytes
     * @return the formatted string
     */
    public String format(long byteCount) {
        String prefix = "";
        if (byteCount == 0) {
            return "0 " + units[0];
        } else if (byteCount < 0) {
            prefix = "-";
            if (byteCount == Long.MIN_VALUE) {
                byteCount++;
            }
            byteCount = -byteCount;
        }
        int digitGroups = (int) (Math.log10(byteCount) / Math.log10(1000));
        return prefix + decimalFormat.format(byteCount / Math.pow(1000, digitGroups)) + " " + units[digitGroups];
    }
}
