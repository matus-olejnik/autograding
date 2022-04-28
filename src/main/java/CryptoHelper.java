import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;

public interface CryptoHelper {
    SecretKey generateKey(int n) throws NoSuchAlgorithmException;

    SecretKey getKeyFromPassword(String password, String salt) throws Exception;

    IvParameterSpec generateIv();

    String encrypt(String algorithm, String input, SecretKey key, IvParameterSpec iv) throws Exception;

    String decrypt(String algorithm, String cipherText, SecretKey key, IvParameterSpec iv) throws Exception;
}
