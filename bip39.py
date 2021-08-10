import os
import sys
import binascii
import hashlib
import hmac
import unicodedata
import base58
from ecdsa import SECP256k1
from ecdsa.ecdsa import Public_key
from web3 import Web3

SECP256k1_GEN = SECP256k1.generator
SECP256k1_ORD = SECP256k1.order

def serialize_curve_point(p):
   x, y = p.x(), p.y()
   if y & 1:
      return b'\x03' + x.to_bytes(32, 'big')
   else:
      return b'\x02' + x.to_bytes(32, 'big')


def curve_point_from_int(k):
   return Public_key(SECP256k1_GEN, SECP256k1_GEN * k).point


def fingerprint_from_private_key(k):
   K = curve_point_from_int(k)
   K_compressed = serialize_curve_point(K)
   identifier = hashlib.new(
      'ripemd160',
      hashlib.sha256(K_compressed).digest(),
   ).digest()
   return identifier[:4]


def derive_ext_private_key(private_key, chain_code, child_number):
    if child_number >= 2 ** 31:
        # Generate a hardened key
        data = b'\x00' + private_key.to_bytes(32, 'big')
    else:
        # Generate a non-hardened key
        p = curve_point_from_int(private_key)
        data = serialize_curve_point(p)
    data += child_number.to_bytes(4, 'big')
    hmac_bytes = hmac.new(chain_code, data, hashlib.sha512).digest()
    L, R = hmac_bytes[:32], hmac_bytes[32:]
    L_as_int = int.from_bytes(L, 'big')
    child_private_key = (L_as_int + private_key) % SECP256k1_ORD
    child_chain_code = R
    return (child_private_key, child_chain_code)














# define number of bits of randomness to use
bits = 256

# generate 32 bytes of random entropy from /urandom module (note urandom not secure, just for experiment purpose)
random_bin = os.urandom(bits//8)
random_hex = random_bin.hex()
print("Entropy: ", random_hex)

# generate a checksum from the SHA256 hash of the entropy bits
sha256_entropy = hashlib.sha256(random_bin).hexdigest()

# concat binary representation of entropy and binary representation of the last 8 bits of the checksum 
entropy_bin = bin(int(random_hex, 16))[2:].zfill(bits)
checksum_bin = bin(int(sha256_entropy, 16))[2:].zfill(bits)[:8]
bin_combined = entropy_bin + checksum_bin


# split combined binary string of entropy and checksum into strings of 11 bits
split_bin = [bin_combined[i:i+11] for i in range(0,len(bin_combined),11)]

# read in word list from Trezor
with open('english.txt', 'r') as f:
    words = [line.strip() for line in f.readlines()]

# map each 11 bits string to an english word based on the BIP-39 dictionary to create a phrase
phrase = [words[int(bin_num,2)] for bin_num in split_bin] 
phrase = ' '.join(phrase)
print("Phrase: ", phrase)


# Phrase to BIP39 SEED
normalized_mnemonic = unicodedata.normalize("NFKD", phrase)
password = ""
normalized_passphrase = unicodedata.normalize("NFKD", password)
salt = "mnemonic" + normalized_passphrase

mnemonic = normalized_mnemonic.encode("utf-8")
salt = salt.encode("utf-8")

# use PBKDF2 to stretch salt using 2048 rounds of hashing with SHA512
seed_bytes = hashlib.pbkdf2_hmac("sha512", mnemonic, salt, 2048)
seed = binascii.hexlify(seed_bytes)
print("Seed: ", seed)


# Ethereum uses Hierarchical Deterministic (HD) wallets as specified by BIP-32
# BIP-44 codifies the purpose of each depth level of hierarchical keys from the seed
# BIP-44 => m / purpose / coin_type / account / change / address_index
# most users of Ethereum uses addresses with a derivation path of m/44'/60'/0'/0/0
# m is just a convention, 44 is for the BIP-44 standard, 60 is coin_type for Ethereum network
# 0 for account, 0 for change (mainly used only in Bitcoin)
# 0 for address_index or index of account you are using
# example: the 10th account is at path m/44'/60'/0'/0/9

# STEP 1: convert seed to a master key or root key
# get HMAC-SHA512 and split resulting 64 bytes into left and right 32 byte sequences:
I = hmac.new(b'Bitcoin seed', seed_bytes, hashlib.sha512).digest()
print('HMAC-SHA512:', I)
L, R = I[:32], I[32:]

master_private_key = int.from_bytes(L, 'big')
master_chain_code = R # note that the chain code mainly serves as entropy for subsequent child key derivations

# 78 bytes are encoded to derive extended keys (a master root key, for example)
VERSION_BYTES = {
    'mainnet_public': binascii.unhexlify('0488b21e'),
    'mainnet_private': binascii.unhexlify('0488ade4'),
    'testnet_public': binascii.unhexlify('043587cf'),
    'testnet_private': binascii.unhexlify('04358394'),
}

version_bytes = VERSION_BYTES['mainnet_private']
depth_byte = b'\x00'
parent_fingerprint = b'\x00' * 4
child_number_bytes = b'\x00' * 4
key_bytes = b'\x00' + L

all_parts = (
    version_bytes,      # 4 bytes  
    depth_byte,         # 1 byte
    parent_fingerprint,  # 4 bytes
    child_number_bytes, # 4 bytes
    master_chain_code,  # 32 bytes
    key_bytes,          # 33 bytes
)

all_bytes = b''.join(all_parts)
root_key = base58.b58encode_check(all_bytes).decode('utf8')

print("Master Root Key: ", root_key)

# STEP 2:  derive child keys
# Break each depth into integers (m/44'/60'/0'/0/0) => (44,60,0,0,0)
# if hardened, add 2**31 to the number => (44 + 2**31, 60 * 2**31, 0 + 2**31, 0, 0)
path_numbers = (44 + 2**31, 60 + 2**31, 0 + 2**31, 0, 0)
depth = 0
parent_fingerprint = None
child_number = None
private_key = master_private_key
chain_code = master_chain_code

for i in path_numbers:
    depth += 1
    child_number = i
    parent_fingerprint = fingerprint_from_private_key(private_key)
    private_key, chain_code = derive_ext_private_key(private_key, chain_code, child_number)

print('Private key for account 0: ', hex(private_key))


# convert private key to a number
k = int(hex(private_key)[2:], 16)

# perform elliptic curve multiplication with generator point and private_key number
ecc_point = Public_key(SECP256k1_GEN, SECP256k1_GEN * k).point

# concat the hex value of elliptic curve x and y coordinates then take Keccak-256 hash to create the public key
concat = hex(ecc_point.x())[2:] + hex(ecc_point.y())[2:] 
public_key = Web3.keccak(hexstr=concat).hex()
print("Public Key: ", public_key)




