'''
| 
| Authors:      Ahmad Khoureich Ka
| Date:         12/2023
|
'''

from charm.toolbox.pairinggroup import PairingGroup
from fabeo22cp import FABEO22CPABE
from ac17 import AC17CPABE
from util import UTIL
import random
import string

def measure_sizes(util,abe,attr_list,policy_str,msg, N=20):
    key_size = 0
    ctxt_size = 0

    for i in range(N):
        # setup
        (pk, msk) = abe.setup()
            
        # encryption
        ctxt = abe.encrypt(pk, msg, policy_str)
        
        # keygen
        key = abe.keygen(pk, msk, attr_list)

        # decryption
        rec_msg = abe.decrypt(pk, ctxt, key)

        if rec_msg != msg:
            print ("Decryption failed.")
            
        if abe.name == 'FAME':
            k_size, c_size = util.fame_key_ctxt_size(key,ctxt, abe.group)
        else:
            k_size, c_size = util.fabeo_key_ctxt_size(key,ctxt, abe.group)
            
        key_size += k_size
        ctxt_size += c_size
    
    return [key_size/N, ctxt_size/N]

def main():
    # choose the scheme to run and policy type
    scheme_name = 'FAME' # FAME | FABEO
    policy_type = 'AND'  # AND | OR
    policy_size = 100
    
    util = UTIL()
    
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('MNT224')
    # generate a random 1KiB (1024 bytes) plaintext
    msg = ''.join(random.choices(string.ascii_letters, k=1024))
    
    if scheme_name == 'FAME':
        scheme = AC17CPABE(pairing_group, 2)
    else:
        scheme = FABEO22CPABE(pairing_group)
        
    if policy_type == 'AND':
        policy_str, attr_list = util.create_policy_string_and_attribute_list_AND_policy(policy_size)
    else:
        policy_str, attr_list = util.create_policy_string_and_attribute_list_OR_policy(policy_size)

    n1,n2,m,i = util.get_par(pairing_group, policy_str, attr_list)
    
    print()
    print('-'*56)
    print(f'{scheme.name} - Storage cost (bytes) - {policy_type} policy: {policy_size}')
    
    key_size, ctxt_size = measure_sizes(util,scheme,attr_list,policy_str,msg)
    
    print('curve MNT224: n1={}  n2={}  m={}  I={}'.format(n1,n2,m,i))
    print('-'*56)
    print('{:^20}'.format('key_size') + '{:^20}'.format('ctxt_size'))
    print('{:^20}'.format(key_size) + '{:^20}'.format(ctxt_size))
    print('-'*56)
    print()
    

if __name__ == "__main__":
    main()
