package encryption;

import encryption.enums.BlockMode;
import encryption.enums.KeyDerivationFunction;
import encryption.enums.PaddingMode;
import encryption.interfaces.PasswordBasedEncryptor;
import encryption.util.SaltGenerator;
import org.apache.commons.io.FilenameUtils;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.SCrypt;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.util.Base64;

/**
 * Base class for encrypting files with password based encryption algorithms (PBE)
 * Used by {@link controller.PasswordBasedEncryptionController}
 *
 * @author Leo Nobis
 */
@SuppressWarnings("SameParameterValue")
public class PasswordBasedEncryption implements PasswordBasedEncryptor {

    // Used for GUI choiceBox
    private final KeyDerivationFunction[] supportedKdf = {KeyDerivationFunction.SHA256, KeyDerivationFunction.SCRYPT};
    // Used for GUI choiceBox
    private final PaddingMode[] supportedPaddingModes = PaddingMode.values();
    // Used for GUI choiceBox
    private final BlockMode[] supportedBlockModes = {BlockMode.GCM, BlockMode.CBC};
    // Used for GUI choiceBox
    private final Integer[] supportedKeyLengths = {256};

    // File to be encrypted
    private File selectedFile;
    // File holding configuration information
    private File configurationFile;
    // PaddingMode used for de/encryption
    private PaddingMode selectedPaddingMode;
    // KDF used for de/encryption
    private KeyDerivationFunction selectedKdf;
    // BlockMode used for de/encryption
    private BlockMode selectedBlockMode;
    // KeyLength used for de/encryption
    private Integer selectedKeyLength;

    // Used to get a cipher instance
    private String transformationString;

    // Used for encryption
    private String password;
    // SecretKey generated from the password
    private SecretKey secretKey;
    // Initialisation Vector used for de/encryption
    private byte[] iv;
    // Salt used for key generation
    private byte[] salt;
    // Used to write config files and de/encrypted files
    private FileWriter fileWriter;

    /**
     * Calculate a derived key using PBKDF2 based on SHA-256 using
     * the BC JCE provider.
     *
     * @param password       the password input.
     * @param salt           the salt parameter.
     * @param iterationCount the iteration count parameter.
     * @return the derived key.
     */
    private static byte[] jcePKCS5Scheme2(char[] password, byte[] salt,
                                          int iterationCount)
            throws GeneralSecurityException {
        SecretKeyFactory fact = SecretKeyFactory.getInstance(
                "PBKDF2WITHHMACSHA256", "BC");

        return fact.generateSecret(
                new PBEKeySpec(password, salt, iterationCount, 256))
                .getEncoded();
    }

    /**
     * Calculate a derived key using SCRYPT using the BC low-level API.
     *
     * @param password             the password input.
     * @param salt                 the salt parameter.
     * @param costParameter        the cost parameter.
     * @param blocksize            the blocksize parameter.
     * @param parallelizationParam the parallelization parameter.
     * @return the derived key.
     */
    private static byte[] bcSCRYPT(char[] password, byte[] salt,
                                   int costParameter, int blocksize,
                                   int parallelizationParam) {
        return SCrypt.generate(
                PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password),
                salt, costParameter, blocksize, parallelizationParam,
                256 / 8);
    }

    /**
     * Create a configuration json file containing information about the used encryption parameters as well as the key.
     * This file can later be used for decryption.
     * Caution: Do not share this file!
     */
    @SuppressWarnings("unchecked") //The json-simple library is compiled with an old bytecode version: 46.0
    private void createConfigFile() {
        JSONObject config = new JSONObject();

        config.put("algorithm", "AES");
        config.put("paddingMode", selectedPaddingMode.toString());
        config.put("blockMode", selectedBlockMode.toString());
        config.put("keyLength", selectedKeyLength.toString());
        config.put("salt", Base64.getEncoder().encodeToString(salt));
        if (this.iv != null) {
            config.put("iv", Base64.getEncoder().encodeToString(iv));
        }

        try {
            fileWriter = new FileWriter(selectedFile.getAbsolutePath() + ".json");
            fileWriter.write(config.toJSONString());
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                fileWriter.flush();
                fileWriter.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Decrypt selected file with configuration
     * init() method has to be called first
     *
     * @throws Exception when file operations go wrong, exceptions are handled in the controller class
     */
    public void decrypt() throws Exception {
        readConfigFile();

        if (selectedKdf == KeyDerivationFunction.SCRYPT) {
            secretKey = generateSecretKeySCRYPT();
        } else if (selectedKdf == KeyDerivationFunction.SHA256) {
            secretKey = generateSecretKeySHA256();
        }

        String fileString = selectedFile.getAbsolutePath().replace(".encrypted", "");

        String filePath = FilenameUtils.getFullPath(fileString);
        String fileBase = FilenameUtils.getBaseName(fileString);
        String fileExtension = FilenameUtils.getExtension(fileString);

        byte[] inputBytes = Files.readAllBytes(selectedFile.toPath());
        byte[] outputBytes = decrypt(inputBytes);
        File outputFile = new File(filePath + fileBase + "_decrypted." + fileExtension);
        Files.write(outputFile.toPath(), outputBytes);
    }

    /**
     * Byte level decryption of a given input using parameters set in the init() function
     *
     * @param input byte representation of the input file
     * @return decrypted file as byte array
     * @throws Exception when file operations go wrong, exceptions are handled in the controller class
     */
    private byte[] decrypt(byte[] input) throws Exception {
        Cipher cipher = Cipher.getInstance(transformationString, "BC");

        if (selectedBlockMode == BlockMode.GCM) {
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        } else if (selectedBlockMode == BlockMode.CBC) {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
        }

        return cipher.doFinal(input);
    }

    /**
     * Encrypt a given input file with parameters set in the init() function
     *
     * @throws Exception when file operations go wrong, exceptions are handled in the controller class
     */
    public void encrypt() throws Exception {
        byte[] inputBytes = Files.readAllBytes(selectedFile.toPath());
        byte[] outputBytes = encrypt(inputBytes);
        File outputFile = new File(selectedFile.getAbsolutePath() + ".encrypted");
        Files.write(outputFile.toPath(), outputBytes);
    }

    /**
     * Byte level encryption of a given input using parameters set in the init() function
     *
     * @param input byte representation of the input file
     * @return encrypted file as byte array
     * @throws Exception when file operations go wrong, exceptions are handled in the controller class
     */
    private byte[] encrypt(byte[] input) throws Exception {
        Cipher cipher = Cipher.getInstance(transformationString, "BC");
        salt = SaltGenerator.getNextSalt();

        // KDF CHECK
        if (selectedKdf == KeyDerivationFunction.SCRYPT) {
            byte[] key = bcSCRYPT(password.toCharArray(), salt, 65536, 128, 1);
            secretKey = new SecretKeySpec(key, 0, key.length, "AES");
            cipher = Cipher.getInstance(transformationString, "BC");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        } else if (selectedKdf == KeyDerivationFunction.SHA256) {
            secretKey = generateSecretKeySHA256();
            cipher = Cipher.getInstance("PBEWithSHA256And128BitAES-CBC-BC", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        }

        // BLOCK MODE CHECK
        if (selectedBlockMode == BlockMode.GCM) {
            AlgorithmParameterGenerator parameterGenerator = AlgorithmParameterGenerator.getInstance("GCM", "BC");
            AlgorithmParameters pGCM = parameterGenerator.generateParameters();
            GCMParameterSpec gcmParameterSpec = pGCM.getParameterSpec(GCMParameterSpec.class);
            this.iv = gcmParameterSpec.getIV();
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, pGCM);
        } else if (selectedBlockMode == BlockMode.CBC) {
            this.iv = cipher.getIV();
        }

        createConfigFile();

        return cipher.doFinal(input);
    }

    /**
     * Generate a SecretKey for SCRYPT generated with the entered password and a salt value
     *
     * @return SecretKey for SCRYPT
     */
    private SecretKey generateSecretKeySCRYPT() {
        byte[] key = bcSCRYPT(password.toCharArray(), salt, 65536, 128, 1);
        return new SecretKeySpec(key, 0, key.length, "AES");
    }

    /**
     * Generate a SecretKey for PBEWithSHA256And128BitAES-CBC
     *
     * @return SecretKey for PBEWithSHA256And128BitAES-CBC
     * @throws Exception when file operations go wrong, exceptions are handled in the controller class
     */
    private SecretKey generateSecretKeySHA256() throws Exception {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, 1000, 256);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithSHA256And128BitAES-CBC-BC");
        return secretKeyFactory.generateSecret(pbeKeySpec);
    }

    /**
     * Generate a string that can be used as a parameter for the Cipher.getInstance() method
     *
     * @return cipher String
     */
    private String generateTransformationString() {
        return "AES" +
                "/" +
                selectedBlockMode +
                "/" +
                selectedPaddingMode;
    }

    /**
     * Getter method for supported block modes
     *
     * @return supported block modes
     */
    @Override
    public BlockMode[] getSupportedBlockModes() {
        return supportedBlockModes;
    }

    /**
     * Getter method for supported key derivation functions
     *
     * @return supported derivation functions
     */
    @Override
    public KeyDerivationFunction[] getSupportedKdf() {
        return supportedKdf;
    }

    /**
     * Getter method for supported key lengths
     *
     * @return supported key lengths
     */
    @Override
    public Integer[] getSupportedKeyLengths() {
        return supportedKeyLengths;
    }

    /**
     * Getter method for supported padding modes
     *
     * @return supported padding modes
     */
    @Override
    public PaddingMode[] getSupportedPaddingModes() {
        return supportedPaddingModes;
    }

    /**
     * Has to be called before using encrypt and decrypt
     * Sets the instance variables of the base class which are used by the en/decrypt functions
     * Also generates the transformationString
     *
     * @param selectedPaddingMode used for en/decryption
     * @param selectedBlockMode   used for en/decryption
     * @param selectedKdf         used for en/decryption
     * @param selectedKeyLength   used for en/decryption
     * @param selectedFile        used for en/decryption
     * @param configurationFile   used for en/decryption
     * @param password            used for en/decryption
     */
    @Override
    public void init(
            PaddingMode selectedPaddingMode,
            BlockMode selectedBlockMode,
            KeyDerivationFunction selectedKdf,
            Integer selectedKeyLength,
            File selectedFile,
            File configurationFile,
            String password) {
        this.selectedPaddingMode = selectedPaddingMode;
        this.selectedBlockMode = selectedBlockMode;
        this.selectedKdf = selectedKdf;
        this.selectedKeyLength = selectedKeyLength;
        this.selectedFile = selectedFile;
        this.configurationFile = configurationFile;
        this.password = password;

        this.transformationString = generateTransformationString();
    }

    /**
     * Read de/encryption parameters from the configuration file
     */
    private void readConfigFile() {
        try {
            FileReader fileReader = new FileReader(configurationFile.getAbsolutePath());
            JSONParser jsonParser = new JSONParser();
            JSONObject jsonObject = (JSONObject) jsonParser.parse(fileReader);

            this.selectedPaddingMode = PaddingMode.valueOf(jsonObject.get("paddingMode").toString());
            this.selectedBlockMode = BlockMode.valueOf(jsonObject.get("blockMode").toString());
            this.selectedKeyLength = Integer.valueOf(jsonObject.get("keyLength").toString());
            this.salt = Base64.getDecoder().decode(jsonObject.get("salt").toString());
            if (jsonObject.get("iv") != null) {
                this.iv = Base64.getDecoder().decode(jsonObject.get("iv").toString());
            }
        } catch (IOException | ParseException e) {
            e.printStackTrace();
        }
    }

    /**
     * Return a name for the GUI
     *
     * @return name for the GUI
     */
    @Override
    public String toString() {
        return "AESPBE";
    }
}
