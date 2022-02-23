package encryption;

import encryption.enums.HashAlgorithm;
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

/**
 * Base class for creating and checking hashes.
 * Used by {@link controller.HashingController}
 *
 * @author Leo Nobis
 */
public class Hashing {

    // Hashing algorithm used in hash function
    private HashAlgorithm selectedAlgorithm;
    // hash loaded from config for hash check
    private byte[] loadedHash;
    // key generated for hashing
    private SecretKey secretKey;

    /**
     * Compute the hash of a file and compare it to a stored hash in another file
     *
     * @param selectedFile file to be checked
     * @param hashFile     file containing the hash that has to match the selectedFile hash
     * @return true if both hashes are equal
     * @throws Exception when file operations go wrong, exceptions are handled in the controller class
     */
    public boolean checkHash(File selectedFile, File hashFile) throws Exception {
        readHashFile(hashFile);

        byte[] hash = hashFile(selectedFile, selectedAlgorithm);
        return Arrays.equals(hash, loadedHash);
    }

    /**
     * Hash a file with a hash algorithm
     * @param selectedFile to be hashed
     * @param selectedAlgorithm to be used for hashing
     * @return hash for selectedFile
     * @throws Exception when file operations go wrong, exceptions are handled in the controller class
     */
    private byte[] hashFile(File selectedFile, HashAlgorithm selectedAlgorithm) throws Exception {
        byte[] data = Files.readAllBytes(selectedFile.toPath());
        byte[] hash;

        switch (selectedAlgorithm) {
            case AESCMAC:
            case HMACSHA256:
                hash = computeMac(selectedAlgorithm.label, secretKey, data);
                break;
            case SHA256:
                hash = computeDigest(selectedAlgorithm.label, data);
                break;
            default:
                hash = new byte[]{};
                break;
        }
        return hash;
    }

    /**
     * Return a digest computed over data using the passed in algorithm
     * digestName.
     *
     * @param digestName the name of the digest algorithm.
     * @param data       the input for the digest function.
     * @return the computed message digest.
     */
    private byte[] computeDigest(String digestName, byte[] data)
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
    private byte[] computeMac(String algorithm, SecretKey key, byte[] data)
            throws NoSuchProviderException, NoSuchAlgorithmException,
            InvalidKeyException {
        Mac mac = Mac.getInstance(algorithm, "BC");

        mac.init(key);

        mac.update(data);

        return mac.doFinal();
    }

    /**
     * Create a configuration file to store the used hash algorithm and hash value.
     * Can later be used to call the check_hash method.
     *
     * @param outputFile        configuration file
     * @param hash              hash to be stored
     * @param selectedAlgorithm algorithm used to calculate the hash
     * @throws Exception when file operations go wrong, exceptions are handled in the controller class
     */
    @SuppressWarnings("unchecked") //The json-simple library is compiled with an old bytecode version: 46.0
    private void createConfigFile(File outputFile, byte[] hash, HashAlgorithm selectedAlgorithm) throws Exception {
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

    /**
     * Hash a input file and put the hash in the output file using a specified hashing algorithm
     *
     * @param inputFile         file to be hashed
     * @param outputFile        file which will store the hash in a json format
     * @param selectedAlgorithm {@link HashAlgorithm} that is used for hashing
     * @throws Exception when file operations go wrong, exceptions are handled in the controller class
     */
    public void hash(File inputFile, File outputFile, HashAlgorithm selectedAlgorithm) throws Exception {
        secretKey = null;
        if (selectedAlgorithm != HashAlgorithm.SHA256) {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
            secretKey = keyGenerator.generateKey();
        }

        byte[] hash = hashFile(inputFile, selectedAlgorithm);
        createConfigFile(outputFile, hash, selectedAlgorithm);
    }

    /**
     * Read a hash and hash algorithm from a file and store it in the base classes instance variables
     *
     * @param hashFile json file containing the hash and the hash algorithm
     */
    private void readHashFile(File hashFile) {
        try {
            FileReader fileReader = new FileReader(hashFile.getAbsolutePath());
            JSONParser jsonParser = new JSONParser();
            JSONObject jsonObject = (JSONObject) jsonParser.parse(fileReader);

            this.selectedAlgorithm = HashAlgorithm.valueOf(jsonObject.get("hashAlgorithm").toString().replace("-", ""));
            this.loadedHash = Base64.getDecoder().decode(jsonObject.get("hash").toString());
            if (jsonObject.get("key") != null) {
                this.secretKey = new SecretKeySpec(Base64.getDecoder().decode(jsonObject.get("key").toString()), selectedAlgorithm.label);
            }
        } catch (IOException | ParseException e) {
            e.printStackTrace();
        }
    }
}
