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
from easyabe import EASYABE
from util import UTIL
import time
import random
import string

def measure_average_times(abe, attr_list, policy_str, msg, N=20):
    sum_setup=0
    sum_enc=0
    sum_keygen=0
    sum_dec=0

    for i in range(N):
        # setup time
        start_setup = time.time()
        (mpk, msk) = abe.setup()
        end_setup = time.time()
        time_setup = end_setup-start_setup
        sum_setup += time_setup
        
        # encryption time
        start_enc = time.time()
        A = abe.get_A(policy_str)
        ctxt = abe.encrypt(mpk, A, msg)
        end_enc = time.time()
        time_enc = end_enc - start_enc
        sum_enc += time_enc

        # keygen time
        start_keygen = time.time()
        w = abe.get_attr_string(attr_list)
        sk = abe.keygen(mpk, msk, w)
        end_keygen = time.time()
        time_keygen = end_keygen - start_keygen
        sum_keygen += time_keygen

        # decryption time
        start_dec = time.time()
        rec_msg = abe.decrypt(ctxt, sk)
        end_dec = time.time()
        time_dec = end_dec - start_dec
        sum_dec += time_dec

        # sanity check
        if rec_msg!= msg:
            print ("Decryption failed.")
    
    # compute average time
    time_setup = sum_setup/N
    time_enc = sum_enc/N
    time_keygen = sum_keygen/N
    time_dec = sum_dec/N

    return [time_setup, time_keygen, time_enc, time_dec]

def print_running_time(times, policy_size):
    print('{:<20}'.format(policy_size) + format(times[0]*1000, '7.2f') + '   ' + format(times[1]*1000, '7.2f') + '  ' + format(times[2]*1000, '7.2f') + '  ' + format(times[3]*1000, '7.2f'))

def run_all(easyabe,policy_size,policy_str, attr_list, msg):
    algos = ['Setup', 'KeyGen', 'Enc', 'Dec']
    
    A = easyabe.get_A(policy_str)

    print('Running times (ms) curve MNT224: |A|={}'.format(len(A)))
    algo_string = '{:<20}'.format(f'{easyabe.name}') + '  ' + algos[0] + '    ' + algos[1] + '     ' + algos[2] + '      ' + algos[3]
    print('-'*56)
    print(algo_string)
    print('-'*56)
    
    easyabe_times = measure_average_times(easyabe, attr_list, policy_str, msg)
    print_running_time(easyabe_times,policy_size)

    print('-'*56)
    print
    

def main():
    # choose the policy type AND | OR
    policy_type = 'OR'
    
    util = UTIL()
    
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('MNT224')

    # choose a random 16 bytes plaintext
    msg = ''.join(random.choices(string.ascii_letters, k=16))
    
    line = '#' + '-'*56
    print(line)
    print(f'EASYABE - {policy_type} policy')
    print(line)
    
    policy_sizes = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    for policy_size in policy_sizes:
        if policy_type == 'AND':
            policy_str, attr_list = util.create_policy_string_and_attribute_list_AND_policy(policy_size)
        else:
            policy_str, attr_list = util.create_policy_string_and_attribute_list_OR_policy(policy_size)
            
        # define attributes of universe
        attr_universe = []
        for i in range(1,policy_size+1):
            attr_universe.append(str(i))
            
        scheme = EASYABE(pairing_group, attr_universe)
        run_all(scheme,policy_size,policy_str, attr_list, msg)

if __name__ == "__main__":
    debug = True
    main()
