Python Implemantation for Two Party MPC ECDSA
-----------------------

This project aims to provide a reference implementation of a secure multiparty computation for elliptic curve signing with two parties.


## Implementation 

The 2P-ECDSA implementation is based on a [blog entry by Nick Money|https://duo.com/labs/tech-notes/2p-ecdsa-explained] about two-party threshold ECDSA proposed by Yehuda Lindell of Bar-Ilan University.

It is an initial reimplementation in Python to learn about and experiment with SMPC variations of partial signing for a next iteration of hardware wallets. Basically built around the tremendous benefit of MPC helping to avoid sending around secrets over networks or to expose secrets and key material over bus systems or during execution within main memory. 

## ToDo

Replace Mike Ivanov's implementation with [Paillier-gmpy2](https://github.com/mnassar/paillier-gmpy2/tree/master/py3)


## Remarks

*Should be compatible with Python >= 3.4.*

Built as an extension to ECPy: http://cslashm.github.io/ECPy/

Paillier Partially Homomorphic Encryption is based on: https://github.com/mikeivanov/paillier

This is explanatory code and not meant for production use
 
## Author & Licence

Copyright (c) 2020 Tom Fuerstner P2-MPC-ECDSA

Copyright (c) 2014 Mike Ivanov Pure Python Paillier Homomorphic Cryptosystem

copyright (c) 2016 Cedric Mesnil ECPy Elliptic Curve library


This program is released under [MIT Licence](LICENCE.txt).
