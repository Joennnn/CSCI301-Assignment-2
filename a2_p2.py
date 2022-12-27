#!/usr/bin/env python3
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import binascii

# Reading scriptPubKey.txt
file_in = open("scriptPubKey.txt", "r")
# Obtaining list of pubkeys
pubkey_content = file_in.readlines() 
file_in.close()

# Reading scriptSig.txt
file_in_sig = open("scriptSig.txt", "rb")
# Obtaining list of signatures
sig_content = file_in_sig.readlines()
file_in_sig.close()

# No. of signatures
numSig = len(sig_content)
# No. of keys
numKey = len(pubkey_content)
counter = 0

message = b"Contemporary topic in security"
hash_obj = SHA256.new(message)

key_arr = []
sig_arr = []

# Unhexing keys
for i in range(1, numKey-1):
	strip_key = pubkey_content[i].strip()
	unhex_key = binascii.unhexlify(strip_key).decode('utf-8')
	key = DSA.import_key(unhex_key)
	key_arr.append(key)

# Unhexing signatures
for j in range(1, numSig):
	strip_sig = sig_content[j].strip()
	unhex_sig = binascii.unhexlify(strip_sig)
	sig_arr.append(unhex_sig)

#Splitting OP_4 + OP_Check
opcode = pubkey_content[5].split()

# Constructing and executing script
print("Beginning script execution...")
print("Pushing ", sig_content[0].decode('utf-8'))
print("Pushing signatures\n")
print("Pushing ", pubkey_content[0])
print("Pushing public keys\n")
print("Pushing ", opcode[0], "\n")
print("Verifying signature with matching public key\n")

# Verifying message
for signature in sig_arr:
	for k in range(len(key_arr)):
		verifier = DSS.new(key_arr[k], 'fips-186-3')
		try:
			verifier.verify(hash_obj, signature)
			counter += 1
			print("Key", k+1, "is authentic. Adding 1 to counter\n")
		except ValueError:
			continue
			

print("Pushing ", opcode[1], "\n")

# Checking message authenticity
if counter == (numSig-1):
	print("The message is authentic.")
else:
	print("The message is not authentic.")
