package easyabe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

/**
 * This class is an implementation Easy-ABE
 * From the paper "Easy-ABE: an Easy Ciphertext-Policy Attribute-Based Encryption"
 * Published in: SECITC 2022
 * Security Assumption: Computational Bilinear Diffie–Hellman Problem in Type-3 (CBDH-3)
 * @author Ahmad Khoureich Ka (ahmadkhoureich.ka@uadb.edu.sn)
 */
public class EasyABE {

    private static final Pairing pairing;
    private static final Field Zr;
    private static final Field G1;
    private static final Field G2;

    private static Element[] msk;
    public static Element[] mpk;

    private static String[] universeOfAttr;

    static {
        Security.addProvider(new BouncyCastleProvider());
        pairing = PairingFactory.getPairing(System.getProperty("user.dir") + "/d496659-224-224.param");

        Zr = pairing.getZr();
        G1 = pairing.getG1();
        G2 = pairing.getG2();
    }

    public static Element H1(String w) throws IOException {
        Element g1 = mpk[0];
        Element g1Alpha = mpk[1];

        BigInteger t = new BigInteger(w, 2);
        Element g1t = g1.pow(t).getImmutable();
        Element hw = g1Alpha.mul(g1t).getImmutable();
        return hw;
    }

    public static Element H2(Element gtElem) {
        return Zr.newElementFromBytes(gtElem.toBytes()).getImmutable();
    }

    public static void setup() {
        System.out.println("--- msk ---");
        Element alpha = Zr.newRandomElement().getImmutable();
        Element beta = Zr.newRandomElement().getImmutable();
        msk = new Element[]{alpha, beta};

        String mskStr = new String(Base64.encode(alpha.toBytes())) + "\n"
                + new String(Base64.encode(beta.toBytes()));
        System.out.println(mskStr);

        System.out.println("--- mpk ---");
        Element g1 = G1.newRandomElement().getImmutable();
        Element g1Alpha = g1.powZn(alpha).getImmutable();
        Element g1Beta = g1.powZn(beta).getImmutable();
        Element g2 = G2.newRandomElement().getImmutable();
        Element g2Beta = g2.powZn(beta).getImmutable();
        mpk = new Element[]{g1, g1Alpha, g1Beta, g2, g2Beta};

        String mpkStr = new String(Base64.encode(g1.toBytes())) + "\n"
                + new String(Base64.encode(g1Alpha.toBytes())) + "\n"
                + new String(Base64.encode(g1Beta.toBytes())) + "\n"
                + new String(Base64.encode(g2.toBytes())) + "\n"
                + new String(Base64.encode(g2Beta.toBytes()));
        System.out.println(mpkStr);
    }

    public static SecretKey keygen(String[] attrSet) throws IOException {
        Element g1 = mpk[0];
        Element g2 = mpk[3];

        Element alpha = msk[0];
        Element beta = msk[1];

        String w = toAttrString(attrSet);
        Element hw = H1(w);

        Element r = Zr.newRandomElement().getImmutable();
        Element hwr = hw.powZn(r).getImmutable();
        Element sk1 = g1.powZn(alpha.mulZn(beta)).mul(hwr).getImmutable();
        Element sk2 = g2.powZn(r).getImmutable();

        SecretKey secretKey = new SecretKey(w, sk1, sk2);
        return secretKey;
    }

    public static CipherText encrypt(String[] accessPolicy, String m) throws Exception {
        Element g1 = mpk[0];
        Element g1Alpha = mpk[1];
        Element g1Beta = mpk[2];
        Element g2 = mpk[3];
        Element g2Beta = mpk[4];

        Element s = Zr.newRandomElement().getImmutable();
        Element eG1AlphaG2BetaS = pairing.pairing(g1Alpha, g2Beta).powZn(s).getImmutable();

        Element sigma = H2(eG1AlphaG2BetaS);

        Element k = Zr.newRandomElement().getImmutable();
        Element g1k = g1.powZn(k).getImmutable();
        Element c1 = g1Beta.mul(g1k).getImmutable();
        Element c1Sigma = c1.powZn(sigma).getImmutable();

        byte[] k1k2 = KDF.kdf(c1Sigma.toBytes(), (SYM.CIPHER_KEYSIZE + MAC.MACSIZE) / 8);
        byte[] k1 = Arrays.copyOf(k1k2, SYM.CIPHER_KEYSIZE / 8);
        byte[] k2 = Arrays.copyOfRange(k1k2, (SYM.CIPHER_KEYSIZE / 8), k1k2.length);

        byte[] c2 = SYM.enc(k1, m);
        byte[] c3 = MAC.mac(c2, k2);
        Element g2s = g2.powZn(s).getImmutable();

        Map<String, Element> hwsMap = new HashMap();
        for (String w : accessPolicy) {
            Element hws = H1(w).powZn(s).getImmutable();
            hwsMap.put(new BigInteger(w, 2).toString(16), hws);
        }

        CipherText cipherText = new CipherText(c1, c2, c3, g2s, hwsMap);
        return cipherText;
    }

    public static void decrypt(CipherText cipherText, SecretKey secretKey) throws IOException, Exception {
        String w = new BigInteger(secretKey.getW(), 2).toString(16);
        Element sk1 = secretKey.getSk1();
        Element sk2 = secretKey.getSk2();

        Element c1 = cipherText.getC1();
        byte[] c2 = cipherText.getC2();
        byte[] c3 = cipherText.getC3();
        Element g2s = cipherText.getG2s();
        Element hws = cipherText.hwsMap.get(w);

        if (hws == null) {
            System.out.println("ABORT hws == null");
            return;
        }

        Element rho1 = pairing.pairing(sk1, g2s).getImmutable();
        Element rho2 = pairing.pairing(hws, sk2).getImmutable();
        Element rho = rho1.div(rho2);
        Element c1Sigma = c1.powZn(H2(rho)).getImmutable();

        byte[] k1k2 = KDF.kdf(c1Sigma.toBytes(), (SYM.CIPHER_KEYSIZE + MAC.MACSIZE) / 8);
        byte[] k1 = Arrays.copyOf(k1k2, SYM.CIPHER_KEYSIZE / 8);
        byte[] k2 = Arrays.copyOfRange(k1k2, (SYM.CIPHER_KEYSIZE / 8), k1k2.length);

        if (!MAC.vrfy(c2, k2, c3)) {
            System.out.println("ABORT vrfy == 0");
            return;
        }

        byte[] pText = SYM.dec(k1, c2);
        System.out.println(new String(pText));
    }

    public static String toAttrString(String[] attrSet) {
        List<String> universeOfAttrList = Arrays.asList(universeOfAttr);

        char[] attrBits = new char[universeOfAttr.length];
        Arrays.fill(attrBits, '0');

        for (String attr : attrSet) {
            if (universeOfAttrList.contains(attr)) {
                int i = universeOfAttrList.indexOf(attr);
                attrBits[attrBits.length - 1 - i] = '1';
            }
        }
        return new String(attrBits);
    }

    public static Element[] getMsk() {
        return msk;
    }

    public static void setMsk(Element[] msk) {
        EasyABE.msk = msk;
    }

    public static Element[] getMpk() {
        return mpk;
    }

    public static void setMpk(Element[] mpk) {
        EasyABE.mpk = mpk;
    }

    public static String[] getUniverseOfAttr() {
        return universeOfAttr;
    }

    public static void setUniverseOfAttr(String[] universeOfAttr) {
        EasyABE.universeOfAttr = universeOfAttr;
    }

    public static Field getZr() {
        return Zr;
    }

    public static Field getG1() {
        return G1;
    }

    public static Field getG2() {
        return G2;
    }

}
