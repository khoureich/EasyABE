'''
| Authors:   Ahmad Khoureich Ka
| Date:           12/2023
'''

from charm.toolbox.pairinggroup import PairingGroup
from easyabe import EASYABE
import random
import string

def run_cpabe(abe, attr_list, policy_str, ptxt):
    (mpk, msk) = abe.setup()
    
    w = abe.get_attr_string(attr_list)
    key = abe.keygen(mpk, msk, w)
    
    A = abe.get_A(policy_str)
    ctxt = abe.encrypt(mpk, A, ptxt)
    
    rec_ptxt = abe.decrypt(ctxt, key)
    
    return rec_ptxt
    
def main():
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('MNT224')
    
    # attribute universe
    attr_universe = ['Degree:Master', 'Degree:Doctoral', 'Field:Education', 'Field:Engineering' , 'AgeGroup:<30']
    policy_str = '(Degree:Doctoral AND AgeGroup:<30) OR (Degree:Master AND Field:Engineering) OR (Degree:Doctoral AND Field:Education)'
    attr_list = ['Degree:Doctoral', 'AgeGroup:<30']
    
    # create an easyabe instance
    easyabe = EASYABE(pairing_group, attr_universe)
    
    # choose a random 64 bytes plaintext
    ptxt = ''.join(random.choices(string.ascii_letters, k=64))
    rec_ptxt = run_cpabe(easyabe, attr_list, policy_str, ptxt)
    
    print()
    print('{:<10}'.format('ptxt:') + ptxt)
    print('{:<10}'.format('rec_ptxt:') + rec_ptxt)
    
    if rec_ptxt == ptxt:
        print("Successful decryption for {}.".format(easyabe.name))
    else:
        print("Decryption failed for {}.".format(easyabe.name))
    print()
      
    
if __name__ == "__main__":
    main()