'''
| 
| Authors:      Ahmad Khoureich Ka
| Date:         12/2023
|
'''

from charm.core.engine.util import objectToBytes,bytesToObject
from charm.toolbox.pairinggroup import PairingGroup
from easyabe import EASYABE
from util import UTIL
import random
import string

def measure_sizes(util,abe,attr_list,policy_str,msg, N=20):
    key_size = 0
    ctxt_size = 0

    for i in range(N):
        # setup time
        (mpk, msk) = abe.setup()
            
        # encryption time
        A = abe.get_A(policy_str)
        ctxt = abe.encrypt(mpk, A, msg)

        # keygen time
        w = abe.get_attr_string(attr_list)
        sk = abe.keygen(mpk, msk, w)

        # decryption time
        rec_msg = abe.decrypt(ctxt, sk)
        #print(rec_msg)

        if rec_msg != msg:
            print ("Decryption failed.")
            
        k_size, c_size = util.easyabe_key_ctxt_size(sk,ctxt, abe.group)
    
        key_size += k_size
        ctxt_size += c_size
    
    return [A, key_size/N, ctxt_size/N]

def main():
    # choose the policy type AND | OR
    policy_type = 'AND'
    policy_size = 100
    
    util = UTIL()
    
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('MNT224')

    # generate a random 1KB (1024 bytes) plaintext
    msg = ''.join(random.choices(string.ascii_letters, k=1024))
    #print(msg)

    # define attributes of universe
    attr_universe = []
    for i in range(1, policy_size+1):
        attr_universe.append(str(i))
        
    scheme = EASYABE(pairing_group, attr_universe)
    
    if policy_type == 'AND':
        policy_str, attr_list = util.create_policy_string_and_attribute_list_AND_policy(policy_size)
    else:
        policy_str, attr_list = util.create_policy_string_and_attribute_list_OR_policy(policy_size)
    
    
    print()
    print('-'*56)
    print(f'{scheme.name} - Storage cost (bytes) - {policy_type} policy: {policy_size}')
    
    A, key_size, ctxt_size = measure_sizes(util,scheme,attr_list,policy_str,msg)
    
    print(f'curve MNT224: |A|={len(A)}')
    print('-'*56)
    print('{:^20}'.format('key_size') + '{:^20}'.format('ctxt_size'))
    print('{:^20}'.format(key_size) + '{:^20}'.format(ctxt_size))
    print('-'*56)
    print()
    
    
if __name__ == "__main__":
    debug = False
    main()
