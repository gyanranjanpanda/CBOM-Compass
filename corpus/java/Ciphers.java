import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;

public class Ciphers {
    public void blockCiphers() throws Exception {
        Cipher ecb = Cipher.getInstance("AES/ECB/PKCS5Padding");
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        Cipher des = Cipher.getInstance("DES");
        Cipher tripleDes = Cipher.getInstance("DESede/CBC/PKCS5Padding");
    }

    public void digests() throws Exception {
        MessageDigest weak = MessageDigest.getInstance("MD5");
        MessageDigest legacy = MessageDigest.getInstance("SHA-1");
        MessageDigest ok = MessageDigest.getInstance("SHA-256");
    }

    public void keys() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        KeyGenerator aes = KeyGenerator.getInstance("AES");
    }

    public void signatures() throws Exception {
        Signature legacy = Signature.getInstance("SHA1withRSA");
        Signature modern = Signature.getInstance("SHA256withECDSA");
    }
}
