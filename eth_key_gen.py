import os
import sys
import hashlib
from web3 import Web3
from ecdsa import SECP256k1
from ecdsa.ecdsa import Public_key

bits = 256

# generate 32 bytes of random entropy from /urandom module (note urandom not secure just for experiment purpose)
random_bin = os.urandom(bits//8)
random_hex = random_bin.hex()
print("Entropy: ", random_hex)

# generate private key as the SHA256 hash of the entropy
private_key = hashlib.sha256(random_bin).hexdigest()
print("Private Key: ", "0x" + private_key)

# convert private key to a number
k = int(private_key,16) 

# get elliptic curve SECP256k1 standard generator point
SECP256k1_GEN = SECP256k1.generator

# perform elliptic curve multiplication with generator point and private_key number
ecc_point = Public_key(SECP256k1_GEN, SECP256k1_GEN * k).point

# concat the hex value of elliptic curve x and y coordinates then take Keccak-256 hash to create the public key
concat = hex(ecc_point.x())[2:] + hex(ecc_point.y())[2:] 
public_key = Web3.keccak(hexstr=concat).hex()
print("Public Key: ", public_key)

# last 20 bytes of private key is public address
address = public_key[-40:]
print("Address: ", "0x" + address)

# convert address to EIP-55 check sum address
addr_hash = Web3.keccak(text=address).hex()[2:42]
check_summed_addr = []

for i, e in enumerate(addr_hash):
    if address[i] in "abcdef" and int(e,16) >= 8:
        check_summed_addr.append(address[i].upper())
    else:
        check_summed_addr.append(address[i])

print("Check Sum Addres: ", "0x" + ''.join(check_summed_addr))