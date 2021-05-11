import os
import binascii
import hashlib
import hmac
import unicodedata
from web3 import Web3

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


