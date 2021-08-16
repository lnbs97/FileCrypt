package encryption;

import encryption.enums.BlockMode;
import encryption.enums.PaddingMode;
import encryption.interfaces.SymmetricalEncryptionAlgorithm;
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

public class SymmetricEncryption implements SymmetricalEncryptionAlgorithm {

    private final PaddingMode[] supportedPaddingModes = PaddingMode.values();
    private final BlockMode[] supportedBlockModes = BlockMode.values();
    private final Integer[] supportedKeyLengths = {128, 192, 256};

    // Init parameters
    private File selectedFile;
    private File configurationFile;
    private PaddingMode selectedPaddingMode;
    private BlockMode selectedBlockMode;
    private Integer selectedKeyLength;

    private String transformationString;

    private SecretKey key;
    private byte[] iv;
    private FileWriter fileWriter;

    private String convertSecretKeyToString(SecretKey secretKey) {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    private SecretKey convertStringToSecretKey(String key) {
        byte[] decodedKey = Base64.getDecoder().decode(key);
        SecretKey secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        return secretKey;
    }

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

    @Override
    public byte[] decrypt(byte[] input) throws Exception {

        Cipher cipher = Cipher.getInstance(transformationString, "BC");

        if (selectedBlockMode == BlockMode.CBC) {
            byte[] iv = this.iv;
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        } else if (selectedBlockMode == BlockMode.GCM) {
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key);
        }

        return cipher.doFinal(input);
    }

    @Override
    public byte[] encrypt(byte[] input) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");

        keyGenerator.init(selectedKeyLength);

        SecretKey key = keyGenerator.generateKey();

        Cipher cipher = Cipher.getInstance(transformationString, "BC");

        cipher.init(Cipher.ENCRYPT_MODE, key);

        if (selectedBlockMode == BlockMode.CBC) {
            this.iv = cipher.getIV();
        } else if (selectedBlockMode == BlockMode.GCM) {
            AlgorithmParameterGenerator parameterGenerator = AlgorithmParameterGenerator.getInstance("GCM", "BC");
            AlgorithmParameters pGCM = parameterGenerator.generateParameters();
            GCMParameterSpec gcmParameterSpec = pGCM.getParameterSpec(GCMParameterSpec.class);
            this.iv = gcmParameterSpec.getIV();
            cipher.init(Cipher.ENCRYPT_MODE, key, pGCM);
        }

        createConfigFile(key);

        byte[] output = cipher.doFinal(input);

        return output;
    }

    public void encrypt() throws Exception {
        byte[] inputBytes = Files.readAllBytes(selectedFile.toPath());
        byte[] outputBytes = encrypt(inputBytes);
        File outputFile = new File(selectedFile.getAbsolutePath() + ".encrypted");
        Files.write(outputFile.toPath(), outputBytes);
    }

    private String generateTransformationString() {
        return "AES" +
                "/" +
                selectedBlockMode +
                "/" +
                selectedPaddingMode;
    }

    @Override
    public BlockMode[] getSupportedBlockModes() {
        return supportedBlockModes;
    }

    @Override
    public Integer[] getSupportedKeyLengths() {
        return supportedKeyLengths;
    }

    @Override
    public PaddingMode[] getSupportedPaddingModes() {
        return supportedPaddingModes;
    }

    /**
     * Has to be called before using encrypt and decrypt
     *
     * @param selectedPaddingMode
     * @param selectedBlockMode
     * @param selectedKeyLength
     * @param configurationFile
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

    @Override
    public String toString() {
        return "AES";
    }

}
