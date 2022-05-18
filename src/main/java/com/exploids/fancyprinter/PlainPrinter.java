package com.exploids.fancyprinter;

import java.io.PrintStream;

/**
 * A printer that ignores all colors and only prints plain text output.
 *
 * @author Luca Selinski
 */
public class PlainPrinter extends FancyPrinterBase {
    /**
     * Creates a new plain printer.
     *
     * @param out the stream to write to
     */
    public PlainPrinter(PrintStream out) {
        super(out);
    }

    @Override
    public void color(Color color) {
    }

    @Override
    public void reset() {
    }
}
