
package easyabe;

import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author Ahmad Khoureich Ka (ahmadkhoureich.ka@uadb.edu.sn)
 */
public class SecretKey {
    private String w;
    private Element sk1;
    private Element sk2;

    public SecretKey(String w, Element sk1, Element sk2) {
        this.w = w;
        this.sk1 = sk1;
        this.sk2 = sk2;
    }

    @Override
    public String toString() {
        return w + "\n"
                + new String(Base64.encode(sk1.toBytes())) + "\n"
                + new String(Base64.encode(sk2.toBytes())) + "\n";
    }

    public String getW() {
        return w;
    }

    public void setW(String w) {
        this.w = w;
    }

    public Element getSk1() {
        return sk1;
    }

    public void setSk1(Element sk1) {
        this.sk1 = sk1;
    }

    public Element getSk2() {
        return sk2;
    }

    public void setSk2(Element sk2) {
        this.sk2 = sk2;
    }
    
            
}
