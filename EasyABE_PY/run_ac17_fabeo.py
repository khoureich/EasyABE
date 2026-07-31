'''
| --- ADAPTED VERSION ---
| Authors:      Ahmad Khoureich Ka
| Date:         12/2023
|
| FROM
|
| https://github.com/DoreenRiepel/FABEO  
| Authors:      Doreen Riepel
| Date:         06/2023
'''

from charm.toolbox.pairinggroup import PairingGroup
from fabeo22cp import FABEO22CPABE
from ac17 import AC17CPABE

import random
import string

def run_cpabe(abe, attr_list, policy_str, ptxt):
    (mpk, msk) = abe.setup()
    key = abe.keygen(mpk, msk, attr_list)
    ctxt = abe.encrypt(mpk, ptxt, policy_str)
    rec_ptxt = abe.decrypt(mpk, ctxt, key)
    
    return rec_ptxt
    
    
def main():
    # choose the scheme to run
    scheme_name = "FABEO" # FAME | FABEO
    
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('MNT224')

    attr_list = ['1', '2', '3']
    policy_str = '((1 and 3) and (2 OR 4))'

    
    if scheme_name == 'FAME':
        scheme = AC17CPABE(pairing_group, 2)
    else:
        scheme = FABEO22CPABE(pairing_group)
    
    # choose a random 64 bytes plaintext
    ptxt = ''.join(random.choices(string.ascii_letters, k=64))
    rec_ptxt = run_cpabe(scheme, attr_list, policy_str, ptxt)
    
    print()
    print('{:<10}'.format('ptxt:') + ptxt)
    print('{:<10}'.format('rec_ptxt:') + rec_ptxt)
    
    if rec_ptxt == ptxt:
        print("Successful decryption for {}.".format(scheme.name))
    else:
        print("Decryption failed for {}.".format(scheme.name))
    print()

if __name__ == "__main__":
    main()
