package easyabe;

import it.unisa.dia.gas.jpbc.Element;
import java.util.Map;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author Ahmad Khoureich Ka (ahmadkhoureich.ka@uadb.edu.sn)
 */
public class CipherText {

    private Element c1;
    private byte[] c2;
    private byte[] c3;
    private Element g2s;
    Map<String, Element> hwsMap;

    public CipherText(Element c1, byte[] c2, byte[] c3, Element g2s, Map<String, Element> hwsMap) {
        this.c1 = c1;
        this.c2 = c2;
        this.c3 = c3;
        this.g2s = g2s;
        this.hwsMap = hwsMap;
    }

    @Override
    public String toString() {

        String r = new String(Base64.encode(c1.toBytes())) + "\n"
                + new String(Base64.encode(c2)) + "\n"
                + new String(Base64.encode(c3)) + "\n"
                + new String(Base64.encode(g2s.toBytes())) + "\n";

        for (String e : hwsMap.keySet()) {
            r += (e + "$" + new String(Base64.encode(hwsMap.get(e).toBytes())) + "\n");
        }

        return r;
    }

    public Element getC1() {
        return c1;
    }

    public void setC1(Element c1) {
        this.c1 = c1;
    }

    public byte[] getC2() {
        return c2;
    }

    public void setC2(byte[] c2) {
        this.c2 = c2;
    }

    public byte[] getC3() {
        return c3;
    }

    public void setC3(byte[] c3) {
        this.c3 = c3;
    }

    public Element getG2s() {
        return g2s;
    }

    public void setG2s(Element g2s) {
        this.g2s = g2s;
    }

    public Map<String, Element> getHwsMap() {
        return hwsMap;
    }

    public void setHwsMap(Map<String, Element> hwsMap) {
        this.hwsMap = hwsMap;
    }

}
