package encryption;

import encryption.enums.BlockMode;
import encryption.enums.KeyDerivationFunction;
import encryption.enums.PaddingMode;
import encryption.interfaces.PasswordBasedEncryptionAlgorithm;
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

public class PasswordBasedEncryption implements PasswordBasedEncryptionAlgorithm {

    KeyDerivationFunction[] supportedKdf = {KeyDerivationFunction.SHA256, KeyDerivationFunction.SCRYPT};
    PaddingMode[] supportedPaddingModes = PaddingMode.values();
    BlockMode[] supportedBlockModes = {BlockMode.GCM, BlockMode.CBC};
    Integer[] supportedKeyLengths = {256};

    // Init parameters
    File selectedFile;
    File configurationFile;
    PaddingMode selectedPaddingMode;
    KeyDerivationFunction selectedKdf;
    BlockMode selectedBlockMode;
    Integer selectedKeyLength;

    String transformationString;

    private String password;
    private SecretKey secretKey;
    private byte[] iv;
    private byte[] salt;
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
    public static byte[] jcePKCS5Scheme2(char[] password, byte[] salt,
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
    public static byte[] bcSCRYPT(char[] password, byte[] salt,
                                  int costParameter, int blocksize,
                                  int parallelizationParam) {
        return SCrypt.generate(
                PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password),
                salt, costParameter, blocksize, parallelizationParam,
                256 / 8);
    }

    public String convertSecretKeyToString(SecretKey secretKey) {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    public SecretKey convertStringToSecretKey(String key) {
        byte[] decodedKey = Base64.getDecoder().decode(key);
        SecretKey secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        return secretKey;
    }

    public void createConfigFile(SecretKey secretKey) {
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

    private SecretKey generateSecretKeySCRYPT() {
        byte[] key = bcSCRYPT(password.toCharArray(), salt, 65536, 128, 1);
        return new SecretKeySpec(key, 0, key.length, "AES");
    }

    @Override
    public byte[] decrypt(byte[] input) throws Exception {
        Cipher cipher = Cipher.getInstance(transformationString, "BC");

        if (selectedBlockMode == BlockMode.GCM) {
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        } else if (selectedBlockMode == BlockMode.CBC) {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
        }

        return cipher.doFinal(input);
    }

    public void encrypt() throws Exception {
        byte[] inputBytes = Files.readAllBytes(selectedFile.toPath());
        byte[] outputBytes = encrypt(inputBytes);
        File outputFile = new File(selectedFile.getAbsolutePath() + ".encrypted");
        Files.write(outputFile.toPath(), outputBytes);
    }

    public SecretKey generateSecretKeySHA256() throws Exception {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, 1000, 256);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithSHA256And128BitAES-CBC-BC");
        return secretKeyFactory.generateSecret(pbeKeySpec);
    }

    @Override
    public byte[] encrypt(byte[] input) throws Exception {
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

        createConfigFile(secretKey);

        byte[] output = cipher.doFinal(input);

        return output;
    }


    public String generateTransformationString() {
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
    public KeyDerivationFunction[] getSupportedKdf() {
        return supportedKdf;
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
     * @param selectedFile
     * @param configurationFile
     * @param password
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

        transformationString = generateTransformationString();
    }

    public void readConfigFile() {
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

    @Override
    public String toString() {
        return "AESPBE";
    }


}
