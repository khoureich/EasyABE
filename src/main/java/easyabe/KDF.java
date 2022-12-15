
package easyabe;

import org.bouncycastle.crypto.generators.KDF1BytesGenerator;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.util.encoders.Hex;

/**
 *
 * @author Ahmad Khoureich Ka (ahmadkhoureich.ka@uadb.edu.sn)
 */
public class KDF {

    public static byte[] kdf(byte[] shared, int outputSize) {
        byte[] iv = Hex.decode("6f1034cebf8a10eb60482aff543be207");
        KDFParameters kdfParam = new KDFParameters(shared, iv);

        byte[] k1k2 = new byte[outputSize];
        KDF1BytesGenerator kdf = new KDF1BytesGenerator(MAC.getHMacDigest(MAC.MACSIZE));
        kdf.init(kdfParam);
        kdf.generateBytes(k1k2, 0, outputSize);

        return k1k2;
    }
}
