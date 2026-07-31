

import random
from msp import MSP
from charm.core.engine.util import objectToBytes,bytesToObject

class UTIL:
    # create policy string and attribute list for a boolean formula of the form "1 and 2 and 3"
    def create_policy_string_and_attribute_list_AND_policy(self, n):
        policy_string = '(1'
        attr_list = ['1']
        for i in range(2,n+1):
            policy_string += ' and ' + str(i)
            attr1 = str(i)
            attr_list.append(attr1)
        policy_string += ')'

        return policy_string, attr_list

    # create policy string and attribute list for a boolean formula of the form "1 or 2 or 3"
    def create_policy_string_and_attribute_list_OR_policy(self, n):
        policy_string = '(1'
        for i in range(2,n+1):
            policy_string += ') or (' + str(i)
        policy_string += ')'

        # select a random attribute
        attr_list = [str(random.randint(1, n))]
        return policy_string, attr_list


    # get parameters of the monotone span program
    def get_par(self,pairing_group, policy_str, attr_list):
        msp_obj = MSP(pairing_group)
        policy = msp_obj.createPolicy(policy_str)
        mono_span_prog = msp_obj.convert_policy_to_msp(policy)
        nodes = msp_obj.prune(policy, attr_list)

        n1 = len(mono_span_prog) # number of rows
        n2 = msp_obj.len_longest_row # number of columns
        m = len(attr_list) # number of attributes
        i = len(nodes) # number of attributes in decryption

        return n1,n2,m,i
            
    def fame_key_ctxt_size(self,key,ctxt, groupObj):
        #key = {'attr_list': attr_list, 'K_0': K_0, 'K': K, 'Kp': Kp}
        k = [key['attr_list'],key['K_0'],key['K'],key['Kp']]
        key_size = len(objectToBytes(k, groupObj))
        
        #ctxt = {'policy': policy, 'C_0': C_0, 'C': C, 'Cp': Cp, 'c_msg':c_msg}
        c_0 = str(ctxt['policy'])
        c_1 = [ctxt["C_0"],ctxt["C"],ctxt["Cp"],ctxt["c_msg"]]
        c_0_size = len(objectToBytes(c_0, groupObj))
        c_1_size = len(objectToBytes(c_1, groupObj))
        ctxt_size = c_0_size + c_1_size
        
        return [key_size, ctxt_size]

    def fabeo_key_ctxt_size(self,key,ctxt, groupObj):
        #key = {'attr_list': attr_list, 'g2_r': g2_r, 'sk1': sk1, 'sk2': sk2}
        k = [key['attr_list'],key['g2_r'],key['sk1'],key['sk2']]
        key_size = len(objectToBytes(k, groupObj))
        
        #ctxt = {'policy': policy, 'g2_s1': g2_s1, 'g2_sprime': g2_sprime, 'ct': ct, 'Cp': Cp, 'c_msg':c_msg}
        c_0 = str(ctxt['policy'])
        c_1 = [ctxt["g2_s1"],ctxt["g2_sprime"],ctxt["ct"],ctxt["Cp"],ctxt["c_msg"]]
        c_0_size = len(objectToBytes(c_0, groupObj))
        c_1_size = len(objectToBytes(c_1, groupObj))
        ctxt_size = c_0_size + c_1_size
        
        return [key_size, ctxt_size]

   
    def easyabe_key_ctxt_size(self,key,ctxt, groupObj):
        #key = {'w':w, 'sk1':sk1, 'sk2':sk2}
        k = [key['w'],key['sk1'],key['sk2']]
        key_size = len(objectToBytes(k, groupObj))
        
        #ctxt = {'c1':c1, 'c2c3':c2c3, 'g2_s':g2_s, 'hws':hws} 
        c = [ctxt["c1"],ctxt["c2c3"],ctxt["g2_s"],ctxt["hws"]]
        c_size = len(objectToBytes(c, groupObj))
        
        return [key_size, c_size]
