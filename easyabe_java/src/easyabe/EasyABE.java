package easyabe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.KDF1BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;

/**
 * From: "Easy-ABE: An Easy Ciphertext-Policy Attribute-Based Encryption"
 *
 * @author Ahmad Khoureich Ka Published in: 2023 Available from:
 * https://eprint.iacr.org/2023/1814 type: ciphertext-policy attribute-based
 * encryption setting: Pairing  - Code authors: Ahmad Khoureich Ka - Date: 12/2023
 */
public class EasyABE {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private String[] attrUniverse;
    private Pairing pairing;
    private Field Zr;
    private Field G1;
    private Field G2;

    private final int SYM_KEYSIZE = 128;
    private final int MAC_SIZE = 256;

    Map<String, Element> msk = new HashMap<>();
    Map<String, Element> mpk = new HashMap<>();

    Map<String, Object> ctxt = new HashMap<>();
    Map<String, Object> sk = new HashMap<>();

    public EasyABE(String curveParam, String[] attrUniverse) {
        this.pairing = PairingFactory.getPairing(curveParam);
        this.Zr = pairing.getZr();
        this.G1 = pairing.getG1();
        this.G2 = pairing.getG2();
        this.attrUniverse = attrUniverse;
    }

    public void setup() {
        // the master secret key
        Element a = Zr.newRandomElement().getImmutable();
        Element b = Zr.newRandomElement().getImmutable();
        msk.put("a", a);
        msk.put("b", b);

        // the master public key
        Element g1 = G1.newRandomElement().getImmutable();
        Element g1A = g1.powZn(a).getImmutable();
        Element g1B = g1.powZn(a).getImmutable();
        Element g2 = G2.newRandomElement().getImmutable();
        Element g2B = g2.powZn(b).getImmutable();
        Element eG1AG2B = pairing.pairing(g1A, g2B).getImmutable();

        mpk.put("g1", g1);
        mpk.put("g1B", g1B);
        mpk.put("g2", g2);
        mpk.put("eG1AG2B", eG1AG2B);
    }

    public Element H1(String w) throws NoSuchAlgorithmException {
        BigInteger t = new BigInteger(w, 2);

        MessageDigest messageDigest = MessageDigest.getInstance("sha1");
        byte[] md = messageDigest.digest(t.toByteArray());

        Element hw = G1.newElementFromBytes(md).getImmutable();
        return hw;
    }

    public Element H2(Element e) {
        return Zr.newElementFromBytes(e.toBytes()).getImmutable();
    }

    public Map<String, Object> keygen(/*mpk, msk,*/String w) throws NoSuchAlgorithmException {
        Element g1 = mpk.get("g1");
        Element g2 = mpk.get("g2");

        Element a = msk.get("a");
        Element b = msk.get("b");

        Element hw = H1(w);

        Element r = Zr.newRandomElement().getImmutable();
        Element hwR = hw.powZn(r).getImmutable();
        Element sk1 = g1.powZn(a.mulZn(b)).mul(hwR).getImmutable();
        Element sk2 = g2.powZn(r).getImmutable();

        sk.put("w", w);
        sk.put("sk1", sk1);
        sk.put("sk2", sk2);

        return sk;
    }

    public Map<String, Object> encrypt(/*mpk,*/List<String> A, String msg) throws Exception {
        Element g1 = mpk.get("g1");
        Element g1B = mpk.get("g1B");
        Element g2 = mpk.get("g2");
        Element eG1AG2B = mpk.get("eG1AG2B");

        Element s = Zr.newRandomElement().getImmutable();
        Element eG1AG2BS = eG1AG2B.powZn(s).getImmutable();

        Element sigma = H2(eG1AG2BS);

        Element k = Zr.newRandomElement().getImmutable();
        Element g1k = g1.powZn(k).getImmutable();
        Element c1 = g1B.mul(g1k).getImmutable();
        Element c1Sigma = c1.powZn(sigma).getImmutable();

        byte[] k1k2 = kdf(c1Sigma.toBytes(), (SYM_KEYSIZE + MAC_SIZE) / 8);
        byte[] k1 = Arrays.copyOf(k1k2, SYM_KEYSIZE / 8);
        byte[] k2 = Arrays.copyOfRange(k1k2, (SYM_KEYSIZE / 8), k1k2.length);

        Map<String, Object> symCtxt = symEnc(k1, Strings.toByteArray(msg));
        byte[] iv = (byte[]) symCtxt.get("iv");
        byte[] c2 = (byte[]) symCtxt.get("c0");

        byte[] c3 = mac(c2, k2);
        Element g2s = g2.powZn(s).getImmutable();

        Map<String, Element> hws = new HashMap();
        for (String w : A) {
            Element hwPowerS = H1(w).powZn(s).getImmutable();
            hws.put(w, hwPowerS);
        }

        ctxt.put("iv", iv);
        ctxt.put("c1", c1);
        ctxt.put("c2", c2);
        ctxt.put("c3", c3);
        ctxt.put("g2s", g2s);
        ctxt.put("hws", hws);

        return ctxt;
    }

    public String decrypt(Map<String, Object> ctxt, Map<String, Object> sk) throws Exception {
        byte[] iv = (byte[]) ctxt.get("iv");
        Element c1 = (Element) ctxt.get("c1");
        byte[] c2 = (byte[]) ctxt.get("c2");
        byte[] c3 = (byte[]) ctxt.get("c3");
        Element g2s = (Element) ctxt.get("g2s");
        Map<String, Element> hws = (Map<String, Element>) ctxt.get("hws");

        String w = (String) sk.get("w");
        Element sk1 = (Element) sk.get("sk1");
        Element sk2 = (Element) sk.get("sk2");

        Element hwPowerS = hws.get(w);

        if (hwPowerS == null) {
            System.out.println("Decryption failed");
            return null;
        }

        Element rho1 = pairing.pairing(sk1, g2s).getImmutable();
        Element rho2 = pairing.pairing(hwPowerS, sk2).getImmutable();
        Element rho = rho1.div(rho2);
        Element c1Sigma = c1.powZn(H2(rho)).getImmutable();

        byte[] k1k2 = kdf(c1Sigma.toBytes(), (SYM_KEYSIZE + MAC_SIZE) / 8);
        byte[] k1 = Arrays.copyOf(k1k2, SYM_KEYSIZE / 8);
        byte[] k2 = Arrays.copyOfRange(k1k2, (SYM_KEYSIZE / 8), k1k2.length);

        if (!vrfy(c2, k2, c3)) {
            System.out.println("Decryption failed");
            return null;
        }

        byte[] ptxt = symDec(k1, c2, iv);

        return new String(ptxt);
    }

    public Map<String, Object> symEnc(byte[] k1, byte[] ptxt) throws Exception {
        SecureRandom sr = new SecureRandom();
        byte[] iv = new byte[16];
        sr.nextBytes(iv);

        SecretKey key = new SecretKeySpec(k1, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] c0 = cipher.doFinal(ptxt);

        Map<String, Object> symCtxt = new HashMap<>();
        symCtxt.put("iv", iv);
        symCtxt.put("c0", c0);
        return symCtxt;
    }

    public byte[] symDec(byte[] k1, byte[] c0, byte[] iv) throws Exception {
        SecretKey key = new SecretKeySpec(k1, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] ptxt = cipher.doFinal(c0);
        return ptxt;
    }

    public byte[] mac(byte[] msg, byte[] k2) {
        Digest digest = new SHA256Digest();
        HMac hmac = new HMac(digest);
        hmac.init(new KeyParameter(k2));
        hmac.update(msg, 0, msg.length);
        byte[] macValue = new byte[hmac.getMacSize()];
        hmac.doFinal(macValue, 0);
        return macValue;
    }

    public boolean vrfy(byte[] msg, byte[] k2, byte[] macValue) {
        byte[] output = mac(msg, k2);
        return new String(macValue).equals(new String(output));
    }

    public byte[] kdf(byte[] shared, int outputSize) {
        KDFParameters kdfParam = new KDFParameters(shared, null);

        byte[] k1k2 = new byte[outputSize];
        KDF1BytesGenerator kdf = new KDF1BytesGenerator(new SHA256Digest());
        kdf.init(kdfParam);
        kdf.generateBytes(k1k2, 0, outputSize);

        return k1k2;
    }

    public String getAttrString(String[] attrSet) {
        String w = "";

        List<String> attrList = Arrays.asList(attrSet);
        for (String s : attrUniverse) {
            if (attrList.contains(s)) {
                w = "1" + w;
            } else {
                w = "0" + w;
            }
        }

        return w;
    }

    public List<String> getA(String policy) {
        List<String> A = new ArrayList<>();

        Pattern p1 = Pattern.compile("\\([\\w\\s:\\-<>]+\\)");
        Matcher m1 = p1.matcher(policy);

        while (m1.find()) {
            String r1 = m1.group();
            r1 = r1.substring(1, r1.length() - 1);
            Pattern p2 = Pattern.compile("\\s+and\\s+|\\s+AND\\s+");
            String[] r2 = p2.split(r1);
            A.add(getAttrString(r2));
        }

        return A;
    }

}