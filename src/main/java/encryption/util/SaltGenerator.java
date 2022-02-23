package encryption.util;

import java.security.SecureRandom;
import java.util.Random;

/**
 * Utility class to generate a random 16 byte salt value
 */
public class SaltGenerator {
    private static final Random RANDOM = new SecureRandom();

    /**
     * Generate salt for PBE algorithms
     *
     * @return a random 16 byte salt
     */
    public static byte[] getNextSalt() {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return salt;
    }
}
