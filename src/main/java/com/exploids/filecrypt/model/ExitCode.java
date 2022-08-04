package com.exploids.filecrypt.model;

import picocli.CommandLine;

public enum ExitCode {
    OK(CommandLine.ExitCode.OK),
    FAILURE(CommandLine.ExitCode.SOFTWARE),
    INSECURE(3),
    IO_ERROR(4),
    NO_SUCH_FILE(5),
    KEY_ERROR(6),
    VERIFICATION_FAILED(7);
    private final int code;

    ExitCode(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }
}
