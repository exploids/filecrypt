package com.exploids.filecrypt.model;

/**
 * All exit codes produced by filecrypt.
 */
public enum ExitCode {
    /**
     * Everything went ok.
     */
    OK(0),

    /**
     * A generic failure.
     */
    FAILURE(1),

    /**
     * A failure caused by wrong usage by the user.
     */
    USAGE(2),

    /**
     * Some parameters would cause insecure encryption and insecure encryption is not explicitly allowed.
     */
    INSECURE(3),

    /**
     * Some generic I/O error occurred.
     */
    IO_ERROR(4),

    /**
     * A file could not be found.
     */
    NO_SUCH_FILE(5),

    /**
     * A key could not be used properly.
     */
    KEY_ERROR(6),

    /**
     * The verification of a MAC/hash failed.
     */
    VERIFICATION_FAILED(7),

    /**
     * The verification of a signature failed.
     */
    INVALID_SIGNATURE(8);

    /**
     * The numeric exit code.
     */
    private final int code;

    /**
     * Instantiates an enum constant.
     *
     * @param code the actual exit code
     */
    ExitCode(int code) {
        this.code = code;
    }

    /**
     * Gets the actual exit code.
     *
     * @return the actual exit code
     */
    public int getCode() {
        return code;
    }
}
