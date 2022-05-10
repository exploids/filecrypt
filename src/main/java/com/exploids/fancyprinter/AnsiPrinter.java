package com.exploids.fancyprinter;

import java.io.PrintStream;

public class AnsiPrinter extends FancyPrinterBase {
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
