package encryption.enums;

public enum HashAlgorithm {
    SHA256("SHA-256"),
    AESCMAC("AESCMAC"),
    HMACSHA256("HMACSHA256");

    public final String label;

    HashAlgorithm(String label) {
        this.label = label;
    }
}
