package encryption.interfaces;

import encryption.enums.BlockMode;
import encryption.enums.PaddingMode;

import java.io.File;

public interface SymmetricalEncryptor extends Encryptor {
    void init(PaddingMode selectedPaddingMode,
              BlockMode selectedBlockMode,
              Integer selectedKeyLength,
              File selectedFile,
              File configurationFile);
}
