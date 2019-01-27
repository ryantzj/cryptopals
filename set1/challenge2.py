"""
Objectives: Write a function that takes two equal-length buffers and produces their XOR combination.
"""

import binascii

string = '1c0111001f010100061a024b53535009181c'
key = '686974207468652062756c6c277320657965'

def encipher_xor(plain, key):
	cipher = bytearray()
	for i in range(len(plain)):
		#cipher.append(chr(plain[i])^chr(key[i]))
		cipher.append(plain[i]^key[i])
	return cipher

def main():
	barray1 = binascii.unhexlify(string)
	barray2 = binascii.unhexlify(key)
	cipher = encipher_xor(barray1,barray2)
	print(binascii.hexlify(cipher))

if __name__ == "__main__":
    main()

