import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public class AES implements EncryptionAlgorithm {

    //TODO richtige Modes einstellen
    PaddingMode[] supportedPaddingModes = PaddingMode.values();
    BlockMode[] supportedBlockModes = BlockMode.values();

    @Override
    public byte[] encrypt(byte[] input) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");

        keyGenerator.init(new SecureRandom());

        SecretKey key = keyGenerator.generateKey();

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");

        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] iv = cipher.getIV();

        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        return cipher.doFinal(input);
    }

    @Override
    public byte[] decrypt(byte[] input) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");

        keyGenerator.init(new SecureRandom());

        SecretKey key = keyGenerator.generateKey();

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");

        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] iv = cipher.getIV();

        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        return cipher.doFinal(input);
    }

    @Override
    public String toString() {
        return "AES";
    }

    @Override
    public PaddingMode[] getSupportedPaddingModes() {
        return supportedPaddingModes;
    }

    @Override
    public BlockMode[] getSupportedBlockModes() {
        return supportedBlockModes;
    }

}
