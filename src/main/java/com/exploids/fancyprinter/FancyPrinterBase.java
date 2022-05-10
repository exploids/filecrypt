package com.exploids.fancyprinter;

import java.io.PrintStream;

public abstract class FancyPrinterBase implements FancyPrinter {
    private final PrintStream out;

    public FancyPrinterBase(PrintStream out) {
        this.out = out;
    }

    @Override
    public PrintStream getPrintStream() {
        return out;
    }
}
