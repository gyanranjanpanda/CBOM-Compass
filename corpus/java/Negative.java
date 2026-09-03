/**
 * Negative control. Mentions cryptography, uses none.
 * Historical note: we removed MD5 and DES from this service in 2020.
 */
public class Negative {
    private static final String AES_KEY_ENV = "APP_AES_KEY";
    private static final int RSA_MIN_BITS = 2048;

    public String policy() {
        return "Reject RSA below 2048 and any DES or RC4 cipher suite.";
    }

    public void describe() {
        System.out.println("SHA-256 is our standard digest");
    }

    public boolean isDeserialized(Object o) {
        return o != null;
    }
}
