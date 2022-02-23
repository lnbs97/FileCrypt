import encryption.Hashing;
import encryption.enums.HashAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.*;

class HashingTest {

    Hashing hashing;
    File testFile = new File("src/test/resources/TestFile.txt");
    File correctHashFile = new File("src/test/resources/TestFile.txt_hash.json");
    File randomFile = new File("src/test/resources/randomFile.txt");
    File outputConfig = new File("src/test/resources/outputconfig");
    HashAlgorithm[] hashAlgorithms = HashAlgorithm.values();

    @BeforeEach
    void setUp() {
        hashing = new Hashing();
    }

    @Test
    void checkHash() throws Exception {
        assertTrue(hashing.checkHash(testFile, correctHashFile));
        assertFalse(hashing.checkHash(randomFile, correctHashFile));
    }

    @Test
    void hash() throws Exception {
        for (HashAlgorithm hashAlgorithm : hashAlgorithms
        ) {
            hashing.hash(testFile, outputConfig, hashAlgorithm);
            assertTrue(hashing.checkHash(testFile, outputConfig));
            assertFalse(hashing.checkHash(randomFile, outputConfig));
        }
    }
}