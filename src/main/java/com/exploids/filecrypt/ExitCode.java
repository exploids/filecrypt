package com.exploids.filecrypt;

import picocli.CommandLine;

public enum ExitCode {
    OK(CommandLine.ExitCode.OK),
    FAILURE(CommandLine.ExitCode.SOFTWARE),
    IO_ERROR(3),
    NO_SUCH_FILE(4),
    KEY_ERROR(5);
    private final int code;

    ExitCode(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }
}
