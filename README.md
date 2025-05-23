# EasyABE
This is the implementation of our scheme "Easy-ABE: An Easy Ciphertext-Policy Attribute-Based Encryption" by Ahmad Khoureich Ka [1].

Attribute-Based Encryption is widely recognized as a leap forward in the field of public key encryption. It allows to enforce an access control on encrypted data [2,3]. Decryption time in ABE schemes can be long depending on the number of attributes and pairing operations. This drawback hinders their adoption on a broader scale.

Easy-ABE is a non-monotone CP-ABE scheme that has no restrictions on the size of attribute sets and policies, allows fast decryption and is adaptively secure under the CBDH-3 assumption. To achieve this, we approached the problem from a new angle, namely using a set membership relation for access structure. Easy-ABE performs better than FAME [4] an FABEO [5].

## Prerequisites
The schemes in the python version are implemented in Python 3.7.17 using the Charm framework [6] version 0.50.

The java version can either be run from the NetBeans IDE or from command line.
To run it from command line follow these steps:<br/> 
1- Download the Bouncy Castle provider (bcprov-ext-jdk18on-177.jar) from https://www.bouncycastle.org/latest_releases.html<br/>
2- Download JPBC from https://sourceforge.net/projects/jpbc/files/jpbc_2_0_0. All the jars files can be found under the jars folder.<br/>
3- Paste the following jars files to the lib directory of the EasyABE directory: bcprov-ext-jdk18on-177.jar, jpbc-api-2.0.0.jar, jpbc-pbc-2.0.0.jar, jpbc-plaf-2.0.0.jar<br/>
4- Make sure the JAVA_HOME environmental variable is set to your Java environment.<br/>
5- Install Apache Ant (for Ubuntu type to your terminal sudo apt install ant).<br/>
6- To run EasyABE change to the its directory and execute the command: ant run

## References

[1] Ka, A.K.: Easy-abe: An easy ciphertext-policy attribute-based encryption. In: Bella, G., Doinea, M., Janicke, H. (eds.) Innovative Security Solutions for Information Technology and Communications. pp. 168–183. Springer Nature Switzerland, Cham (2023). Extended version available on ePrint Archive, Report [2023/1814](https://eprint.iacr.org/2023/1814)

[2] Goyal, Vipul, Omkant Pandey, Amit Sahai, and Brent Waters. "Attribute-based encryption for fine-grained access control of encrypted data." In Proceedings of the 13th ACM conference on Computer and communications security, pp. 89-98. ACM, 2006. Full version available on ePrint Archive, Report [2006/309](https://eprint.iacr.org/2006/309).

[3] Bethencourt, John, Amit Sahai, and Brent Waters. "Ciphertext-policy attribute-based encryption." In Security and Privacy, 2007. SP'07. IEEE Symposium on, pp. 321-334. IEEE, 2007.

[4] Agrawal, S., Chase, M.: Fame: Fast attribute-based message encryption. CCS ’17, Association for Computing Machinery, New York, NY, USA (2017), https://doi.org/10.1145/3133956.3134014

[5] Riepel, D., Wee, H.: Fabeo: Fast attribute-based encryption with optimal security. In: Proceedings of the 2022 ACM SIGSAC Conference on Computer and Communications Security. p. 2491–2504. CCS ’22, Association for Computing Machinery, New York, NY, USA (2022). https://doi.org/10.1145/3548606.3560699, https://doi.org/10.1145/3548606.3560699

[6] Akinyele, J.A., Garman, C., Miers, I., Pagano, M.W., Rushanan, M., Green, M., Rubin, A.D.: Charm: a framework for rapidly prototyping cryptosystems. Journal of Cryptographic Engineering 3(2), 111–128 (2013). https://doi.org/10.1007/s13389-013-0057-3
