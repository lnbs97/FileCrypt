package encryption.interfaces;

import encryption.BlockMode;
import encryption.KeyDerivationFunction;
import encryption.PaddingMode;

import java.io.File;

public interface PasswordBasedEncryptionAlgorithm extends EncryptionAlgorithm{
    void init(PaddingMode selectedPaddingMode,
              BlockMode selectedBlockMode,
              KeyDerivationFunction selectedKdf,
              Integer selectedKeyLength,
              File selectedFile,
              File configurationFile,
              String password);

    KeyDerivationFunction[] getSupportedKdf();
}
