package encryption.interfaces;

import encryption.enums.BlockMode;
import encryption.enums.KeyDerivationFunction;
import encryption.enums.PaddingMode;

import java.io.File;

public interface PasswordBasedEncryptor extends Encryptor {
    void init(PaddingMode selectedPaddingMode,
              BlockMode selectedBlockMode,
              KeyDerivationFunction selectedKdf,
              Integer selectedKeyLength,
              File selectedFile,
              File configurationFile,
              String password);

    KeyDerivationFunction[] getSupportedKdf();
}
