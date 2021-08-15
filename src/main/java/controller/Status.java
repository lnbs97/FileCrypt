package controller;

enum Status {
    SELECT_FILE("Please select a file!"),
    SELECT_CONFIG("Please select a configuration file!"),
    SELECT_ALGORITHM("Please select an algorithm!"),
    READY("Ready for de/encryption"),
    ILLEGAL_BLOCKSIZE("Block Size not aligned. Please choose another padding mode!"),
    NO_SUCH_PADDING("Only NoPadding can be used with AEAD modes!"),
    MAC_CHECK_FAILED("MAC check failed! The file might have been manipulated!"),
    WRONG_PASSWORD("Wrong password or file might have been manipulated!"),
    ENCRYPTION_SUCCESSFUL("Encryption successful!"),
    ENCRYPTION_FAILED("Encryption failed!"),
    DECRYPTION_SUCCESSFUL("Decryption successful!"),
    DECRYPTION_FAILED("Decryption failed!");

    public final String label;

    Status(String label) {
        this.label = label;
    }
}
