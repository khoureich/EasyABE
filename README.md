# An Easy Ciphertext-Policy Attribute-Based Encryption
Attribute-Based Encryption is widely recognized as a leap forward in the field of public key encryption. It allows to enforce an access control on encrypted data [1]. Easy-ABE [2] is a Ciphertext-Policy Attribute-Based Encryption (CP-ABE) scheme. In a CP-ABE scheme [3], the access policy is embedded in the ciphertext and users secret keys are associated with sets of attributes. Users wishing to decrypt the ciphertext must have the necessary attributes to satisfy the ciphertext's built-in access control.

## Prerequisites
To compile and run EasyABE, you need the Java Pairing-Based Cryptography Library (JPBC) [4].

## References
[1] Goyal, Vipul, Omkant Pandey, Amit Sahai, and Brent Waters. "Attribute-based encryption for fine-grained access control of encrypted data." In Proceedings of the 13th ACM conference on Computer and communications security, pp. 89-98. ACM, 2006. Full version available on ePrint Archive, Report [2006/309](https://eprint.iacr.org/2006/309).<br/>
[2] Bethencourt, John, Amit Sahai, and Brent Waters. "Ciphertext-policy attribute-based encryption." In Security and Privacy, 2007. SP'07. IEEE Symposium on, pp. 321-334. IEEE, 2007.<br/>
[3] Ahmad Khoureich Ka. "Easy-ABE: An Easy Ciphertext-Policy Attribute-Based Encryption" will appear in the proceedings of SecITC2022. <br/>
[4] De Caro, A., Iovino, V.: jpbc: Java pairing based cryptography. In: Proceedings of the 16th IEEE Symposium on Computers and Communications, ISCC2011. pp. 850–855. IEEE, Kerkyra, Corfu, Greece, June 28 - July 1 (2011), http://gas.dia.unisa.it/projects/jpbc/<br/>
