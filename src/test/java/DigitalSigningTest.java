import encryption.DigitalSigning;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DigitalSigningTest {

    File testFile = new File("src/test/resources/TestFile.txt");
    File randomFile = new File("src/test/resources/randomFile.txt");
    File outputConfig = new File("src/test/resources/outputconfig");
    File correctSignatureFile = new File("src/test/resources/TestFile.txt_sig.json");

    @BeforeEach
    void setUp() {
    }

    @Test
    void sign() throws Exception {
        DigitalSigning.sign(testFile, outputConfig);
        assertTrue(DigitalSigning.verify(testFile, outputConfig));
        assertFalse(DigitalSigning.verify(randomFile, outputConfig));
    }

    @Test
    void verify() throws Exception {
        assertTrue(DigitalSigning.verify(testFile, correctSignatureFile));
        assertFalse(DigitalSigning.verify(randomFile, correctSignatureFile));
    }
}