

string = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
alphanumeric = b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

def singleCharXOR(input_bytes, key):
		cipher = b''
		for byte in input_bytes:
			#print(byte)
			#print(key)
			cipher += bytes([byte^key])
		
		return cipher
		#try:
		#print(cipher)
		#except:
		#	print("error")




def main():
	ciphertext= bytes.fromhex(string)

	for key_value in range(127):
		cipher = singleCharXOR(ciphertext,key_value)
		print(cipher)




if __name__ == "__main__":
	main()
