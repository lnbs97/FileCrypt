package encryption;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Base64;


public class Hashing {

    private HashAlgorithm selectedAlgorithm;
    private byte[] loadedHash;
    private SecretKey secretKey;

    public void hash(File selectedFile, File outputFile, HashAlgorithm selectedAlgorithm) throws Exception {
        secretKey = null;
        if (selectedAlgorithm != HashAlgorithm.SHA256) {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
            secretKey = keyGenerator.generateKey();
        }

        byte[] data = Files.readAllBytes(selectedFile.toPath());
        byte[] hash;

        switch (selectedAlgorithm) {
            case AESCMAC:
                hash = computeMac(selectedAlgorithm.label, secretKey, data);
                break;
            case SHA256:
                hash = computeDigest(selectedAlgorithm.label, data);
                break;
            case HMACSHA256:
                hash = computeMac(selectedAlgorithm.label, secretKey, data);
                break;
            default:
                hash = new byte[]{};
                break;
        }
        createConfigFile(outputFile, hash, selectedAlgorithm);
    }

    public boolean check_hash(File selectedFile, File hashFile) throws Exception {
        readHashFile(hashFile);

        byte[] data = Files.readAllBytes(selectedFile.toPath());
        byte[] hash;

        switch (selectedAlgorithm) {
            case AESCMAC:
                hash = computeMac(selectedAlgorithm.label, secretKey, data);
                break;
            case SHA256:
                hash = computeDigest(selectedAlgorithm.label, data);
                break;
            case HMACSHA256:
                hash = computeMac(selectedAlgorithm.label, secretKey, data);
                break;
            default:
                hash = new byte[]{};
                break;
        }
        return Arrays.equals(hash, loadedHash);
    }

    public void createConfigFile(File outputFile, byte[] hash, HashAlgorithm selectedAlgorithm) throws Exception {
        JSONObject config = new JSONObject();
        FileWriter fileWriter = new FileWriter(outputFile.getAbsolutePath());

        String hashString = Base64.getEncoder().encodeToString(hash);

        config.put("hashAlgorithm", selectedAlgorithm.label);
        config.put("hash", hashString);
        if (secretKey != null) {
            config.put("key", Base64.getEncoder().encodeToString(secretKey.getEncoded()));
        }

        try {
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

    public void readHashFile(File hashFile) {
        try {
            FileReader fileReader = new FileReader(hashFile.getAbsolutePath());
            JSONParser jsonParser = new JSONParser();
            JSONObject jsonObject = (JSONObject) jsonParser.parse(fileReader);

            this.selectedAlgorithm = HashAlgorithm.valueOf(jsonObject.get("hashAlgorithm").toString().replace("-",""));
            this.loadedHash = Base64.getDecoder().decode(jsonObject.get("hash").toString());
            if (jsonObject.get("key") != null) {
                this.secretKey = new SecretKeySpec(Base64.getDecoder().decode(jsonObject.get("key").toString()), selectedAlgorithm.label);
            }
        } catch (IOException | ParseException e) {
            e.printStackTrace();
        }
    }

    /**
     * Return a digest computed over data using the passed in algorithm
     * digestName.
     *
     * @param digestName the name of the digest algorithm.
     * @param data       the input for the digest function.
     * @return the computed message digest.
     */
    public byte[] computeDigest(String digestName, byte[] data)
            throws NoSuchProviderException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(digestName, "BC");

        digest.update(data);

        return digest.digest();
    }

    /**
     * Return a MAC computed over data using the passed in MAC algorithm
     * type algorithm.
     *
     * @param algorithm the name of the MAC algorithm.
     * @param key       an appropriate secret key for the MAC algorithm.
     * @param data      the input for the MAC function.
     * @return the computed MAC.
     */
    public byte[] computeMac(String algorithm, SecretKey key, byte[] data)
            throws NoSuchProviderException, NoSuchAlgorithmException,
            InvalidKeyException {
        Mac mac = Mac.getInstance(algorithm, "BC");

        mac.init(key);

        mac.update(data);

        return mac.doFinal();
    }
}
