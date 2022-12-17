package main;

import easyabe.CipherText;
import easyabe.EasyABE;
import easyabe.SecretKey;
import java.util.Arrays;

/**
 *
 * @author Ahmad Khoureich Ka (ahmadkhoureich.ka@uadb.edu.sn)
 */
public class Main {

    public static void main(String[] args) throws Exception {

        String ptext = "Keep it easy & crypto.";
//
        System.out.println("--- SETUP ---");
//      Using MNT224 curve  
        String curveParam = System.getProperty("user.dir") + "/d496659-224-224.param";
        EasyABE.setup(curveParam);
//
//        --- Universe of attributes---
        String[] universeOfAttr = {
            "Student-Status:Degree",
            "Student-Status:Non-degree",
            "Student-Status:Special",
            "Student-Status:Conditional",
            "AgeGroup:18-25",
            "AgeGroup:>25",
            "Citizenship:AAA"};
        EasyABE.setUniverseOfAttr(universeOfAttr);
        System.out.println("\nUniverse ot attributes: "+Arrays.toString(universeOfAttr));
//        
        System.out.println("Access policy = (Student-Status:Degree OR Student-Status:Conditional) AND (AgeGroup:18-25) AND (Citizenship:AAA)");
//
        System.out.println("\n--- KEYGEN ---");
        String[] attrSet1 = {"Student-Status:Degree", "AgeGroup:18-25", "Citizenship:AAA"};
        SecretKey secretKey1 = EasyABE.keygen(attrSet1);
        System.out.println("Attribute set: "+Arrays.toString(attrSet1));
        System.out.println(secretKey1);
//
//        System.out.println("\n--- KEYGEN ---");
//        String[] attrSet2 = {"Student-Status:Conditional", "AgeGroup:18-25", "Citizenship:AAA"};
//        System.out.println("Attribute set: "+Arrays.toString(attrSet2));
//        SecretKey secretKey2 = EasyABE.keygen(attrSet2);
//        System.out.println(secretKey2);
//
        System.out.println("--- ENCRYPT ---");
        String[] accessPolicy = {"1010001", "1011000"};
        CipherText cipherText = EasyABE.encrypt(accessPolicy, ptext);
        System.out.println(cipherText);
        
        System.out.println("--- DECRYPT ---");
        EasyABE.decrypt(cipherText, secretKey1);
    }
}
