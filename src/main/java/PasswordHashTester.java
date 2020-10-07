import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * A class for testing whether a hash of a password matches a given hash.
 */
public class PasswordHashTester {
    String password = "<Your password here>";
    String salt = "<Your salt here>";
    String compareHash = "<Your compare hash here>";

    private static String toHex(byte[] array) throws NoSuchAlgorithmException {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if(paddingLength > 0) {
            return String.format("%0"  + paddingLength + "d", 0) + hex;
        }else{
            return hex;
        }
    }

    public static String getHash(String pwd, String salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        int iterations = 10000;
        char[] chars = pwd.toCharArray();
        PBEKeySpec spec = new PBEKeySpec(chars, salt.getBytes(), iterations, 4096 );
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        byte[] hash = skf.generateSecret(spec).getEncoded();
        return toHex(hash);
    }

    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException {
        PasswordHashTester hasher = new PasswordHashTester();

        String generatedHash = getHash(
                hasher.password,
                hasher.salt);

        System.out.println(generatedHash);

        System.out.println("Is this generated hash correct?");
        System.out.println(generatedHash.equals(hasher.compareHash));
    }
}
