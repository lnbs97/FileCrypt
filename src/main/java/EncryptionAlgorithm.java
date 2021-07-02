public interface EncryptionAlgorithm {

    byte[] encrypt(byte[] input) throws Exception;
    byte[] decrypt(byte[] input) throws Exception;

    String toString();
    PaddingMode[] getSupportedPaddingModes();
    BlockMode[] getSupportedBlockModes();
}
