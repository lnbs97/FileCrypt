package encryption;

import encryption.enums.BlockMode;
import encryption.enums.PaddingMode;
import encryption.interfaces.SymmetricalEncryptor;
import org.apache.commons.io.FilenameUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.util.Base64;

/**
 * Base class for encrypting files with symmetric encryption algorithms
 * Used by {@link controller.SymmetricEncryptionController}
 *
 * @author Leo Nobis
 */
public class SymmetricEncryption implements SymmetricalEncryptor {

    // Used for GUI choiceBox
    private final PaddingMode[] supportedPaddingModes = PaddingMode.values();
    // Used for GUI choiceBox
    private final BlockMode[] supportedBlockModes = BlockMode.values();
    // Used for GUI choiceBox
    private final Integer[] supportedKeyLengths = {128, 192, 256};

    // File to be encrypted
    private File selectedFile;
    // File holding configuration information
    private File configurationFile;
    // PaddingMode used for de/encryption
    private PaddingMode selectedPaddingMode;
    // BlockMode used for de/encryption
    private BlockMode selectedBlockMode;
    // KeyLength used for de/encryption
    private Integer selectedKeyLength;

    // Used to get a cipher instance
    private String transformationString;

    // generated SecretKey
    private SecretKey key;
    // Initialisation Vector used for de/encryption
    private byte[] iv;
    // Used to write config files and de/encrypted files
    private FileWriter fileWriter;

    /**
     * Convert a SecretKey to a String
     *
     * @param secretKey to be converted
     * @return String representing the bytes of the key
     */
    private String convertSecretKeyToString(SecretKey secretKey) {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    /**
     * Convert a String which contains a SecretKey to a SecretKey object
     *
     * @param key String that contains the key information
     * @return SecretKey object
     */
    private SecretKey convertStringToSecretKey(String key) {
        byte[] decodedKey = Base64.getDecoder().decode(key);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    /**
     * Create a configuration json file containing information about the used encryption parameters as well as the key.
     * This file can later be used for decryption.
     * Caution: Do not share this file!
     */
    @SuppressWarnings("unchecked") //The json-simple library is compiled with an old bytecode version: 46.0
    private void createConfigFile(SecretKey secretKey) {
        JSONObject config = new JSONObject();

        config.put("algorithm", "AES");
        config.put("paddingMode", selectedPaddingMode.toString());
        config.put("blockMode", selectedBlockMode.toString());
        config.put("keyLength", selectedKeyLength.toString());
        config.put("key", convertSecretKeyToString(secretKey));

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

        if (selectedBlockMode == BlockMode.CBC
                || selectedBlockMode == BlockMode.CTS
                || selectedBlockMode == BlockMode.OFB) {
            byte[] iv = this.iv;
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        } else if (selectedBlockMode == BlockMode.GCM) {
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
        } else if (selectedBlockMode == BlockMode.CCM) {
            GCMParameterSpec spec = new GCMParameterSpec(128, this.iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            cipher.updateAAD("0000".getBytes());
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key);
        }

        return cipher.doFinal(input);
    }

    /**
     * Byte level encryption of a given input using parameters set in the init() function
     *
     * @param input byte representation of the input file
     * @return encrypted file as byte array
     * @throws Exception when file operations go wrong, exceptions are handled in the controller class
     */
    private byte[] encrypt(byte[] input) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");

        keyGenerator.init(selectedKeyLength);

        SecretKey key = keyGenerator.generateKey();

        Cipher cipher = Cipher.getInstance(transformationString, "BC");

        cipher.init(Cipher.ENCRYPT_MODE, key);

        if (selectedBlockMode == BlockMode.CBC
                || selectedBlockMode == BlockMode.CTS
                || selectedBlockMode == BlockMode.OFB
        ) {
            this.iv = cipher.getIV();
        } else if (selectedBlockMode == BlockMode.GCM) {
            AlgorithmParameterGenerator parameterGenerator = AlgorithmParameterGenerator.getInstance("GCM", "BC");
            AlgorithmParameters pGCM = parameterGenerator.generateParameters();
            GCMParameterSpec gcmParameterSpec = pGCM.getParameterSpec(GCMParameterSpec.class);
            this.iv = gcmParameterSpec.getIV();
            cipher.init(Cipher.ENCRYPT_MODE, key, pGCM);
        } else if (selectedBlockMode == BlockMode.CCM) {
            this.iv = cipher.getIV();
            GCMParameterSpec spec = new GCMParameterSpec(128, this.iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            cipher.updateAAD("0000".getBytes());
        }

        createConfigFile(key);

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
     * @param selectedKeyLength   used for en/decryption
     * @param selectedFile        used for en/decryption
     * @param configurationFile   used for en/decryption
     */
    public void init(PaddingMode selectedPaddingMode,
                     BlockMode selectedBlockMode,
                     Integer selectedKeyLength,
                     File selectedFile,
                     File configurationFile) {
        this.selectedPaddingMode = selectedPaddingMode;
        this.selectedBlockMode = selectedBlockMode;
        this.selectedKeyLength = selectedKeyLength;
        this.selectedFile = selectedFile;
        this.configurationFile = configurationFile;

        transformationString = generateTransformationString();
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
            this.key = convertStringToSecretKey(jsonObject.get("key").toString());
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
        return "AES";
    }
}