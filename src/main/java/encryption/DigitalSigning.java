package encryption;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class DigitalSigning {

    private static byte[] encSignature;
    private static PublicKey publicKey;

    public static void sign(File inputFile, File outputFile) throws Exception {
        byte[] file = Files.readAllBytes(inputFile.toPath());

        KeyPair keyPair = generateDSAKeyPair();
        publicKey = keyPair.getPublic();

        byte[] dsaSignature = generateDSASignature(keyPair.getPrivate(), file);
        createSignatureFile(dsaSignature, outputFile);
    }


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
    public static KeyPair generateDSAKeyPair()
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
    public static byte[] generateDSASignature(PrivateKey dsaPrivate, byte[] input)
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
    public static boolean verifyDSASignature(
            PublicKey dsaPublic, byte[] input, byte[] encSignature)
            throws GeneralSecurityException {
        Signature signature = Signature.getInstance("SHA256withDSA", "BC");

        signature.initVerify(dsaPublic);

        signature.update(input);

        return signature.verify(encSignature);
    }

    public static boolean verify(File inputFile, File signature) throws Exception {
        readConfigFile(signature);
        byte[] inputFileBytes = Files.readAllBytes(inputFile.toPath());
        return verifyDSASignature(publicKey, inputFileBytes, encSignature);
    }

    public static void readConfigFile(File configurationFile) {
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
