import os
import sys
import hashlib
from web3 import Web3
from ecdsa import SECP256k1
from ecdsa.ecdsa import Public_key

def gen_private_key():
    entropy = os.urandom(32)
    private_key = hashlib.sha256(entropy).hexdigest()
    return private_key


def to_checksum_address(public_key):
    # get last 20 bytes of public_key
    address = public_key[-40:]

    # convert address to EIP-55 check sum address
    addr_hash = Web3.keccak(text=address).hex()[2:42]
    check_summed_addr = []

    for i, e in enumerate(addr_hash):
        if address[i] in "abcdef" and int(e,16) >= 8:
            check_summed_addr.append(address[i].upper())
        else:
            check_summed_addr.append(address[i])

    return "0x" + ''.join(check_summed_addr)

def calc_public_key(private_key):
    # convert private key to a number
    k = int(private_key,16) 

    # get elliptic curve SECP256k1 standard generator point
    SECP256k1_GEN = SECP256k1.generator

    # perform elliptic curve multiplication with generator point and private_key number
    ecc_point = Public_key(SECP256k1_GEN, SECP256k1_GEN * k).point

    # concat the hex value of elliptic curve x and y coordinates then take Keccak-256 hash to create the public key
    concat = hex(ecc_point.x())[2:] + hex(ecc_point.y())[2:] 
    public_key = Web3.keccak(hexstr=concat).hex()
    return to_checksum_address(public_key)


# take input from command line 

if len(sys.argv) > 1:
    num_accounts = int(sys.argv[1])
else:
    num_accounts = 1


for i in range(num_accounts):
    print("-----------------------------------------------")
    private_key = gen_private_key()
    public_key = calc_public_key(private_key)
    print("Private Key: ", private_key)
    print("Public Key: ", public_key)
    