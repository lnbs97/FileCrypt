package encryption.interfaces;

import encryption.enums.BlockMode;
import encryption.enums.PaddingMode;

public interface Encryptor {

    void encrypt() throws Exception;

    void decrypt() throws Exception;

    String toString();

    PaddingMode[] getSupportedPaddingModes();

    BlockMode[] getSupportedBlockModes();

    Integer[] getSupportedKeyLengths();

}
