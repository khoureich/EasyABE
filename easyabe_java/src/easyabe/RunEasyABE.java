package easyabe;

import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;

/**
 * From: "Easy-ABE: An Easy Ciphertext-Policy Attribute-Based Encryption"
 *
 * @author Ahmad Khoureich Ka Published in: 2023 Available from:
 * https://eprint.iacr.org/2023/1814 type: ciphertext-policy attribute-based
 * encryption setting: Pairing  - Code authors: Ahmad Khoureich Ka - Date: 12/2023
 */
public class RunEasyABE {

    public static void main(String[] args) throws NoSuchAlgorithmException, Exception {
        // choose curve
        String curveParam = System.getProperty("user.dir") + "/d496659-224-224.param";

        // attribute universe
        String[] attrUniverse = {"Degree:Master", "Degree:Doctoral", "Field:Education", "Field:Engineering" , "AgeGroup:<30", "azerty"};
        String policy =    "(Degree:Doctoral AND AgeGroup:<30) OR (Degree:Master AND Field:Engineering) OR (Degree:Doctoral AND Field:Education)";
        

        // create an easyabe instance
        EasyABE easyabe = new EasyABE(curveParam, attrUniverse);
        
        // run the set up
        easyabe.setup();

        // generate a key
        String[] attrSet = {"Degree:Doctoral", "AgeGroup:<30"};
        String w = easyabe.getAttrString(attrSet);
        Map<String, Object> sk = easyabe.keygen(w);

        // encrypt a message
        String msg = "Keep it easy & crypto.";
        List<String> A = easyabe.getA(policy);
        Map<String, Object> ctxt = easyabe.encrypt(A, msg);

        // decryption
        String recMsg = easyabe.decrypt(ctxt, sk);

        System.out.println("msg:\t" + msg);
        System.out.println("recMsg:\t" + recMsg);
        if (msg.equals(recMsg)) {
            System.out.println("Successful decryption.");
        } else {
            System.out.println("Decryption failed.");
        }

    }

}