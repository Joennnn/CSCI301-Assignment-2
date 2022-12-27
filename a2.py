#!/usr/bin/env python3
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import binascii
import random

key_arr = []
hex_pubkey = []
signature_arr = []

# Generating first key and domain
key = DSA.generate(2048)
domain = key.domain()

# Appending first key 
key_arr.append(key)
pubkey =  key.publickey().export_key()

# Hexing key
pubkey_hex = binascii.hexlify(pubkey)
hex_pubkey.append(pubkey_hex)

# Obtaining keys
for i in range(3):
	key = DSA.generate(2048, domain = domain)
	key_arr.append(key)
	pubkey =  key.publickey().export_key()
	pubkey_hex = binascii.hexlify(pubkey)
	hex_pubkey.append(pubkey_hex)
	
# Writing key in scriptPubKey
with open("scriptPubKey.txt", "wb") as file:
	file.write(b"OP_2\n")
	for i in hex_pubkey:
		file.write(i)
		file.write(b"\n")
	file.write(b"OP_4 OP_CHECKMULTSIG")
	print("scriptPubKey.txt has been generated")

# Writing signature in scriptSig 
with open("scriptSig.txt", "w") as file:
	file.write("OP_1\n")

message = b"Contemporary topic in security"

for i in range(2):
	x = random.randint(0,3)
	hash_obj = SHA256.new(message)
	signer = DSS.new(key_arr[x], 'fips-186-3')
	signature = signer.sign(hash_obj)
	signature_hex = binascii.hexlify(signature)
	signature_arr.append(signature_hex)

	# Writing singature into scriptSig
	with open("scriptSig.txt", "ab") as file:
		file.write(signature_hex)
		file.write(b"\n")
	
print("scriptSig.txt has been generated\n")

