#!/usr/bin/env python3

import os
import hashlib

from paillier import *
from primes import *

from ecpy.curves     import Curve,Point
from ecpy.keys       import ECPublicKey, ECPrivateKey
from ecpy.ecdsa      import ECDSA

curve = Curve.get_curve('secp256k1')
n = curve.order
G = curve.generator

ur_1 = random.randrange(1, n) % n
d1 = ECPrivateKey(ur_1, curve)
ec_pub_1 = d1.get_public_key()

ur_2 = random.randrange(1, n) % n
d2 = ECPrivateKey(ur_2, curve)
ec_pub_2 = d2.get_public_key()


k1 = random.randrange(1, n) % n
k2 = random.randrange(1, n) % n

k1 = k1 % n
k2 = k2 % n


z = 0xc493cb789beba59cd1db18ff5e5ccf30a39e63d49b03d86f2d5cb5ae2d5e2e44

p = k1 * G * k2
print("The point p = ", p)

r = p.x % n
print("hier kommt der r wert", hex(r))


print( "Generating keypair...")
pllr_priv_1, pllr_pub_1 = generate_keypair(512)
pllr_priv_2, pllr_pub_2 = generate_keypair(512)



''' P_1 shares ckey = Enc(d_1) with P_2 '''
ckey = encrypt(pllr_pub_1, d1.d) 
print("ckey_1 = ", ckey)

''' P_2 computes k_2^-1 * z and encrypts it to the Paillier pubkey of P_1, producing Enc(k_2^-1 * z) '''
k2inv = pow(k2,n-2,n)
ckey_2 = k2inv * z
ckey_2 = encrypt(pllr_pub_1,ckey_2)
print("ckey_2 = ", ckey_2)


''' P_2 computes k_2^-1 * r * d_2. This is a scalar value, so with access to ckey but no knowledge of d_1, 
    P_2 can now compute Enc(k_2^-1 * r * d_2 * d_1)
'''
ckey_3 = k2inv * r * d2.d 
print("ckey_3 = ", ckey_3)

ckey_4 = e_mul_const(pllr_pub_1, ckey, ckey_3 )
print("ckey_4 = ", ckey_4)


''' P_2 now has two ciphertexts encrypted under the Paillier pubkey of P_1, which thanks to homomorphism, 
    it can add together, producing Enc(k_2^-1 * z + k_2^-1 * r * d_2 * d_1)
'''

ciphertext = e_add(pllr_pub_1, ckey_2, ckey_4)
print("ciphertext = ", ciphertext)

plaintext = decrypt(pllr_priv_1, pllr_pub_1, ciphertext )
k1inv = pow(k1,n-2,n)
s = (k1inv * plaintext) % n
print("r = ", hex(r))
print("s = ", hex(s))


"""
Calculate the message hash, using a cryptographic hash function like SHA-256: h = hash(msg)
Generate securely a random number k in the range [1..n-1]
In case of deterministic-ECDSA, the value k is HMAC-derived from h + privKey (see RFC 6979)
Calculate the random point R = k * G and take its x-coordinate: r = R.x
Calculate the signature proof: s = 
The modular inverse  is an integer, such that 
Return the signature {r, s}.
"""

h = z
k = k1 * k2 
k = k % n
R = k * G
r = R.x
print(hex(R.x))

s1 = pow(k,n-2,n)
d = d1.d * d2.d
s2 = h + r * d
s = (s1 * s2) % n
print(hex(s))

print("\n\n")
print("SIGN Process")
print("\n\n")

h = z
R = k * G
r = R.x
print(hex(R.x))
#s1 = invmod(k_1, cv.order) 
s1 = pow(k,n-2,n)
s2 = h + r * d
s = (s1 * s2) % n
print(hex(s))
print(hex(r))


print("\n\n")
print("VALIDATION Process")
print("\n\n")

h = z
pubkey = d * G
# s1 = invmod(s, cv.order)
s1 = pow(s,n-2,n)
Rh = ((h * s1) * G) + (r * s1) * pubkey
rh = Rh.x
print(hex(rh))