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
    DECRYPTION_FAILED("Decryption failed!"),
    VERIFY_FAILED("Signature verification failed!"),
    VERIFY_SUCCESSFUL("Signature verification successful!"),
    SIGNING_SUCCESSFUL("Document Signing successful!"),
    SIGNING_FAILED("Document Signing failed!"),
    READY_SIGNING("Ready for Signing / Verification!");

    String label;

    Status(String label) {
        this.label = label;
    }
}
