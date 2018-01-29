import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
 
public class TestPolicyFiles {
 
    public static void main(String[] args) {
        try {
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(256);
            SecretKey key = keygen.generateKey();
            Cipher aes = Cipher.getInstance("AES/CBC/PKCS5PAdding");
            aes.init(Cipher.ENCRYPT_MODE, key);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}