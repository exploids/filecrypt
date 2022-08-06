package com.exploids.filecrypt.model;

public enum PasswordAlgorithm {
    SHA256(256 / 8),
    SHA(160 / 8),
    SCRYPT(256 / 8);

    private final int saltSize;

    PasswordAlgorithm(int saltSize) {
        this.saltSize = saltSize;
    }

    public String getAlgorithmName(int keySize, Algorithm cipherAlgorithm, BlockMode blockMode) {
        if (this == SCRYPT) {
            return "SCRYPT";
        } else if (cipherAlgorithm.isStream()) {
            return String.format("PBEWith%sAnd%dBit%s", this, keySize, cipherAlgorithm);
        } else {
            return String.format("PBEWith%sAnd%dBit%s-%s-BC", this, keySize, cipherAlgorithm, blockMode);
        }
    }

    public int getSaltSize() {
        return saltSize;
    }
}
