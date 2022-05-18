package com.exploids.fancyprinter;

import java.io.PrintStream;

/**
 * Prints stuff to a print stream, but more fancy.
 *
 * @author Luca Selinski
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

    /**
     * A convenience method that calls {@link #reset()} and prints a newline.
     */
    default void resetNewLine() {
        reset();
        getPrintStream().println();
    }

    /**
     * Convenience method that calls {@link PrintStream#printf(String, Object...)} using a color.
     *
     * @param color      the text color
     * @param format     the format string
     * @param parameters the arguments for the format string
     */
    default void printf(Color color, String format, Object... parameters) {
        color(color);
        getPrintStream().printf(format, parameters);
        reset();
    }
}
