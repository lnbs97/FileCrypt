package encryption;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Base class for signing files and verifying signed files.
 * Used by {@link controller.DigitalSigningController}
 *
 * @author Leo Nobis
 */
public class DigitalSigning {

    // generated file signature
    private static byte[] encSignature;
    // public key for hash checking on recipient side
    private static PublicKey publicKey;

    /**
     * Create a signature for an input file and store it in the output file in JSON format
     *
     * @param inputFile  file to be signed
     * @param outputFile file where to signature will be written to
     * @throws Exception when file operations go wrong, exceptions are handled in the controller class
     */
    public static void sign(File inputFile, File outputFile) throws Exception {
        byte[] file = Files.readAllBytes(inputFile.toPath());

        KeyPair keyPair = generateDSAKeyPair();
        publicKey = keyPair.getPublic();

        byte[] dsaSignature = generateDSASignature(keyPair.getPrivate(), file);
        createSignatureFile(dsaSignature, outputFile);
    }

    /**
     * Create a signature file in JSON format from a provided DSA Signature. The file contains the signature and a public key to check it
     *
     * @param dsaSignature dsa private key encrypted signature
     * @param outputFile   file where to signature and public key will be written to
     * @throws IOException when file operations go wrong, exceptions are handled in the controller class
     */
    @SuppressWarnings("unchecked") //The json-simple library is compiled with an old bytecode version: 46.0
    private static void createSignatureFile(byte[] dsaSignature, File outputFile) throws IOException {
        JSONObject config = new JSONObject();
        FileWriter fileWriter = new FileWriter(outputFile);

        String signature = Base64.getEncoder().encodeToString(dsaSignature);
        String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());

        config.put("signature", signature);
        config.put("publicKey", publicKeyString);

        fileWriter.write(config.toJSONString());

        fileWriter.flush();
        fileWriter.close();
    }


    /**
     * Generate a 2048 bit DSA key pair using provider based parameters.
     *
     * @return a DSA KeyPair
     */
    private static KeyPair generateDSAKeyPair()
            throws GeneralSecurityException {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("DSA", "BC");

        keyPair.initialize(2048);

        return keyPair.generateKeyPair();
    }

    /**
     * Generate an encoded DSA signature using the passed in private key and
     * input data.
     *
     * @param dsaPrivate the private key for generating the signature with.
     * @param input      the input to be signed.
     * @return the encoded signature.
     */
    private static byte[] generateDSASignature(PrivateKey dsaPrivate, byte[] input)
            throws GeneralSecurityException {
        Signature signature = Signature.getInstance("SHA256withDSA", "BC");

        signature.initSign(dsaPrivate);

        signature.update(input);

        return signature.sign();
    }

    /**
     * Return true if the passed in signature verifies against
     * the passed in DSA public key and input.
     *
     * @param dsaPublic    the public key of the signature creator.
     * @param input        the input that was supposed to have been signed.
     * @param encSignature the encoded signature.
     * @return true if the signature verifies, false otherwise.
     */
    private static boolean verifyDSASignature(
            PublicKey dsaPublic, byte[] input, byte[] encSignature)
            throws GeneralSecurityException {
        Signature signature = Signature.getInstance("SHA256withDSA", "BC");

        signature.initVerify(dsaPublic);

        signature.update(input);

        return signature.verify(encSignature);
    }

    /**
     * Verify if a file was signed with a signature
     *
     * @param inputFile file to be verified
     * @param signature file containing the signature and the public key
     * @return true if the signature verifies against the input file and public key, false otherwise
     * @throws Exception when file operations go wrong, exceptions are handled in the controller class
     */
    public static boolean verify(File inputFile, File signature) throws Exception {
        readConfigFile(signature);
        byte[] inputFileBytes = Files.readAllBytes(inputFile.toPath());
        return verifyDSASignature(publicKey, inputFileBytes, encSignature);
    }

    /**
     * Read the public key and the signature from the configuration file and store them in the instance variables
     *
     * @param configurationFile json file containing signature and public key
     */
    private static void readConfigFile(File configurationFile) {
        try {
            FileReader fileReader = new FileReader(configurationFile.getAbsolutePath());
            JSONParser jsonParser = new JSONParser();
            JSONObject jsonObject = (JSONObject) jsonParser.parse(fileReader);

            String publicKeyString = jsonObject.get("publicKey").toString();
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
            publicKey = KeyFactory.getInstance("DSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));

            String signature = jsonObject.get("signature").toString();
            encSignature = Base64.getDecoder().decode(signature);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
