package com.exploids.fancyprinter;

import java.io.PrintStream;

/**
 * A printer that uses ANSI escape codes to enable colored output.
 *
 * @author Luca Selinski
 */
public class AnsiPrinter extends FancyPrinterBase {
    /**
     * Creates a new ansi printer.
     *
     * @param out the stream to write to
     */
    public AnsiPrinter(PrintStream out) {
        super(out);
    }

    @Override
    public void color(Color color) {
        getPrintStream().print(color.getAnsi());
    }

    @Override
    public void reset() {
        getPrintStream().print("\u001B[0m");
    }
}
