package com.exploids.fancyprinter;

import java.io.PrintStream;

public class PlainPrinter extends FancyPrinterBase {
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
