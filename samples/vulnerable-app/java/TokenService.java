import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;

public class TokenService {
    public void weakCipher() throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        Cipher legacy = Cipher.getInstance("DES");
    }
    public void keys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        KeyGenerator kg = KeyGenerator.getInstance("AES");
    }
    public void digests() throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        MessageDigest ok = MessageDigest.getInstance("SHA-256");
        Signature sig = Signature.getInstance("SHA1withRSA");
    }
}
