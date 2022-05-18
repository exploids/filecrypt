package com.exploids.fancyprinter;

/**
 * A color.
 *
 * @author Luca Selinski
 */
public enum Color {
    BLACK,
    RED,
    GREEN,
    YELLOW,
    BLUE,
    PURPLE,
    CYAN,
    WHITE;

    /**
     * Gets the ansi escape code corresponding to the color.
     *
     * @return the ansi escape code
     */
    public String getAnsi() {
        return "\u001B[" + (30 + ordinal()) + "m";
    }
}
