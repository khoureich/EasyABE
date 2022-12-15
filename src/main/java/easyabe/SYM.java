
package easyabe;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 *
 * @author Ahmad Khoureich Ka (ahmadkhoureich.ka@uadb.edu.sn)
 */
public class SYM {
    public static final int CIPHER_KEYSIZE = 128; // 128, 192, 256

    public static byte[] enc(byte[] k1, String pText) throws Exception {
        SecretKey key = new SecretKeySpec(k1, "AES");
        byte[] iv = Hex.decode("b088eda7a7c7a78e031e42e4e1b48190");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] cText = cipher.doFinal(Strings.toByteArray(pText));
        return cText;
    }

    public static byte[] dec(byte[] k1, byte[] cText) throws Exception {
        SecretKey key = new SecretKeySpec(k1, "AES");
        byte[] iv = Hex.decode("b088eda7a7c7a78e031e42e4e1b48190");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] pText = cipher.doFinal(cText);
        return pText;
    }
    
}
