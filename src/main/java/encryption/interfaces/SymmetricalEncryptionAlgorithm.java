package encryption.interfaces;

import encryption.BlockMode;
import encryption.PaddingMode;

import java.io.File;

public interface SymmetricalEncryptionAlgorithm extends EncryptionAlgorithm {
    void init(PaddingMode selectedPaddingMode,
              BlockMode selectedBlockMode,
              Integer selectedKeyLength,
              File selectedFile,
              File configurationFile);
}