package encryption.interfaces;

import encryption.enums.BlockMode;
import encryption.enums.PaddingMode;

public interface EncryptionAlgorithm {

    void encrypt() throws Exception;

    void decrypt() throws Exception;

    byte[] encrypt(byte[] input) throws Exception;

    byte[] decrypt(byte[] input) throws Exception;

    String toString();

    PaddingMode[] getSupportedPaddingModes();

    BlockMode[] getSupportedBlockModes();

    Integer[] getSupportedKeyLengths();


}
