import encryption.SymmetricEncryption;
import encryption.enums.BlockMode;
import encryption.enums.PaddingMode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.*;

class SymmetricEncryptionTest {

    SymmetricEncryption symmetricEncryption;

    PaddingMode[] paddingModes;
    BlockMode[] blockModes;
    Integer[] keyLengths;

    @BeforeEach
    void setUp() {
        symmetricEncryption = new SymmetricEncryption();
        paddingModes = symmetricEncryption.getSupportedPaddingModes();
        blockModes = symmetricEncryption.getSupportedBlockModes();
        keyLengths = symmetricEncryption.getSupportedKeyLengths();
    }

    /**
     * Tests encrypt as well as decrypt.
     *
     * Tests all possible combinations of padding, blockmode and keylength
     * and asserts that the decrypted file is equal to the original file
     * and that the decrypted file is not equal to the encrypted file
     */
    @Test
    void encrypt() {
        File testFile = new File("src/test/resources/TestFile.txt");

        for (PaddingMode paddingMode : paddingModes
        ) {
            for (BlockMode blockMode : blockModes
            ) {
                for (Integer keyLength : keyLengths
                ) {
                    symmetricEncryption.init(paddingMode, blockMode, keyLength, testFile, null);

                    // Test some exceptions
                    switch (blockMode) {
                        case GCM:
                            if (paddingMode != PaddingMode.NoPadding) {
                                assertThrows(NoSuchPaddingException.class,
                                        () -> symmetricEncryption.encrypt());
                            }
                            break;
                        case CBC:
                            if (paddingMode == PaddingMode.NoPadding) {
                                assertThrows(IllegalBlockSizeException.class,
                                        () -> symmetricEncryption.encrypt());
                            }
                            break;
                    }
                    try {
                        // test the whole encryption and decryption process
                        symmetricEncryption.encrypt();
                        File encryptedFile = new File("src/test/resources/TestFile.txt.encrypted");
                        File configurationFile = new File("src/test/resources/TestFile.txt.json");
                        symmetricEncryption.init(paddingMode, blockMode, keyLength, encryptedFile, configurationFile);
                        symmetricEncryption.decrypt();
                        File decryptedFile = new File("src/test/resources/TestFile_decrypted.txt");

                        byte[] testFileBytes = Files.readAllBytes(testFile.toPath());
                        byte[] encryptedFileBytes = Files.readAllBytes(encryptedFile.toPath());
                        byte[] decryptedFileBytes = Files.readAllBytes(decryptedFile.toPath());

                        assertArrayEquals(testFileBytes, decryptedFileBytes);
                        assertNotEquals(encryptedFileBytes, decryptedFileBytes);

                    } catch (Exception e) {
                        System.out.println("PaddingMode: " + paddingMode);
                        System.out.println("BlockMode: " + blockMode);
                        System.out.println("KeyLength: " + keyLength);
                        e.printStackTrace();
                    }
                }
            }
        }
    }
}