
package easyabe;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 *
 * @author Ahmad Khoureich Ka (ahmadkhoureich.ka@uadb.edu.sn)
 */
public class MAC {
    public static final int MACSIZE = 256;        // 256, 384, 512

    public static byte[] mac(byte[] message, byte[] k2) {
        Digest digest = getHMacDigest(MACSIZE);
        HMac hmac = new HMac(digest);
        hmac.init(new KeyParameter(k2));
        hmac.update(message, 0, message.length);
        byte[] macValue = new byte[hmac.getMacSize()];
        hmac.doFinal(macValue, 0);
        return macValue;
    }

    public static boolean vrfy(byte[] message, byte[] k2, byte[] macValue) {
        byte[] output = mac(message, k2);
        return new String(macValue).equals(new String(output));
    }

    public static Digest getHMacDigest(int macSize) {
        return switch (macSize) {
            case 256 ->
                new SHA256Digest();
            case 384 ->
                new SHA384Digest();
            case 512 ->
                new SHA512Digest();
            default ->
                new SHA512Digest();
        };
    }
    
}
