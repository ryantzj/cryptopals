"""
Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal
Encrypt it, under the key "ICE", using repeating-key XOR.
"""

string = b"Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"
key = 'ICE'
repeatedKey = b'ICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEIC'

def repeatedXOR(input_bytes, key):
		cipher = b''
		for i in range(len(input_bytes)):
				cipher += bytes([input_bytes[i]^key[i]])
			
		return cipher

def main():
	cipher1 = repeatedXOR(string,repeatedKey)
	print(bytes.hex(cipher1))




if __name__ == "__main__":
	main()

"""
0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
"""

