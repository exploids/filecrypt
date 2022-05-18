package com.exploids.fancyprinter;

import java.io.PrintStream;

/**
 * A base for {@link FancyPrinter} implementations.
 *
 * @author Luca Selinski
 */
public abstract class FancyPrinterBase implements FancyPrinter {
    /**
     * The underlying stream to write to.
     */
    private final PrintStream out;

    /**
     * Creates a new base instance.
     *
     * @param out the stream to write to
     */
    public FancyPrinterBase(PrintStream out) {
        this.out = out;
    }

    @Override
    public PrintStream getPrintStream() {
        return out;
    }
}
