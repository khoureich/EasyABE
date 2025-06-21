'''
| From: "Easy-ABE: An Easy Ciphertext-Policy Attribute-Based Encryption"
| Authors: Ahmad Khoureich Ka
| Published in: 2023
| Available from: https://eprint.iacr.org/2023/1814
|
| type:           ciphertext-policy attribute-based encryption
| setting:        Pairing
| Code authors:   Ahmad Khoureich Ka
| Date:           12/2023
'''

from charm.toolbox.pairinggroup import ZR, G1, G2, GT, pair, extract_key
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction
from charm.core.math.pairing import hashPair
import random
import re

debug = False

class EASYABE():
    def __init__(self, group_obj, attr_universe):
        self.name = 'EASYABE'
        self.group = group_obj
        self.attr_universe = attr_universe
        
    def setup(self):
        if debug:
            print('\nSetup algorithm:\n')
            
        # pick generators g1 and g2 for G1 and G2 respectively
        g1 = self.group.random(G1)
        g2 = self.group.random(G2)
        
        # choose two random exponents alpha, beta from ZR
        a = self.group.random(ZR)
        b = self.group.random(ZR)
        
        # compute g1_alph, g1_beta, g2_beta and e_g1alpha_g2beta
        g1_a = g1**a
        g1_b = g1**b
        g2_b = g2**b
        e_g1a_g2b = pair(g1_a,g2_b)
        
        # the public key
        mpk = {'g1':g1, 'g1_b':g1_b, 'g2':g2, 'e_g1a_g2b':e_g1a_g2b}

        # the master secret key
        msk = {'a':a, 'b':b}
        
        return mpk, msk

    def H1(self, w):
        r = str(int(w, 2))
        hw = self.group.hash(r, G1)
        return hw

    def H2(self, e):
        val1 = hashPair(e)
        val2 = self.group.hash(val1, ZR)
        return val2
    
    def keygen(self, mpk, msk, w):
        if debug:
            print('\nKey generation algorithm:\n')
            
        g1 = mpk['g1']
        g2 = mpk['g2']
        a = msk['a']
        b = msk['b']
                
        hw = self.H1(w)
        r = self.group.random(ZR)
        
        g1_ab = g1**(a*b)
        hw_r = hw**r
        g2_r = g2**r
        
        sk1 = g1_ab*hw_r
        sk2 = g2_r
        
        sk = {'w':int(w, 2), 'sk1':sk1, 'sk2':sk2}
        
        return sk
    
    def encrypt(self, mpk, A, msg):
        if debug:
            print('\nEncryption algorithm:\n')
            
        g1 = mpk['g1']
        g1_b = mpk['g1_b']
        g2 = mpk['g2']
        e_g1a_g2b = mpk['e_g1a_g2b']
        
        s = self.group.random(ZR)
        e_g1a_g2b_s = e_g1a_g2b**s
        sigma = self.H2(e_g1a_g2b_s)
        
        k = self.group.random(ZR)
        c1 = g1_b*(g1**k)
        c1_sigma = c1**sigma
        dhies = AuthenticatedCryptoAbstraction(extract_key(c1_sigma))
        c2c3 = dhies.encrypt(msg)
        
        g2_s = g2**s
        
        hws = {}
        for w in A:
            hw = self.H1(w)
            _w = str(int(w, 2))
            hws[_w] = hw**s
            
        ctxt = {'c1':c1, 'c2c3':c2c3, 'g2_s':g2_s, 'hws':hws} 
        return ctxt
    
    def decrypt(self, ctxt, sk):
        if debug:
            print('\nDecryption algorithm:\n')
            
        _w = sk['w']
        sk1 = sk['sk1']
        sk2 = sk['sk2']
        
        c1 = ctxt['c1']
        c2c3 = ctxt['c2c3']
        g2_s = ctxt['g2_s']
        hws = ctxt['hws']
        
        if str(_w) in hws:
            rho1 = pair(sk1,g2_s)
            rho2 = pair(hws[str(_w)], sk2)
            rho = rho1/rho2
            sigma = self.H2(rho)
            c1_sigma = c1**sigma
            dhies = AuthenticatedCryptoAbstraction(extract_key(c1_sigma))
            ptxt = dhies.decrypt(c2c3)
            return ptxt.decode("utf-8")
        else:
            print('Decryption failed')
            
            
    # get attribute string from sttribute list
    def get_attr_string(self, attr_list):
        w = ''
        for i in range(len(self.attr_universe)):
            if self.attr_universe[i].lower() in (item.lower() for item in attr_list):
                w = '1' + w
            else:
                w = '0' + w
            
        return w

    # get authorized attribute strings from policy of the form (A and B and ...) or (C and ...) ... or (D)
    def get_A(self, policy):
        A = []
        r = re.findall(r"\([\w\s:\-<>]+\)", policy)
        for a in r:
            r1 = re.findall(r"\((.+)\)", a)
            r2 = re.split(r'\s+and\s+|\s+AND\s+',r1[0])
            A.append(self.get_attr_string(r2))
    
        return A     
    
