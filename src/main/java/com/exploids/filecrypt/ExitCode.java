package com.exploids.filecrypt;

public enum ExitCode {
    OK(0),
    FAILURE(1),
    KEY_ERROR(10);
    private final int code;

    ExitCode(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }
}
