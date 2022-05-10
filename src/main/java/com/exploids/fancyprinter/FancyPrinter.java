package com.exploids.fancyprinter;

import java.io.PrintStream;

/**
 * Prints stuff to a print stream, but more fancy.
 */
public interface FancyPrinter {
    /**
     * Gets a print stream to put text into.
     *
     * @return the print stream
     */
    PrintStream getPrintStream();

    /**
     * Prints following characters in the specified color.
     *
     * @param color the color
     */
    void color(Color color);

    /**
     * Resets all styles to the default.
     */
    void reset();

    default void resetNewLine() {
        reset();
        getPrintStream().println();
    }

    default void printf(Color color, String format, Object... parameters) {
        color(color);
        getPrintStream().printf(format, parameters);
        reset();
    }
}
