"""
One of the 60-character strings in this file has been encrypted by single-character XOR.


"""

def singleCharXOR(input_bytes, key):
		cipher = b''
		for byte in input_bytes:
			cipher += bytes([byte^key])
		
		return cipher

def readFile():
	with open('4.txt') as f:
		lines = f.read().splitlines()
	return lines

def frequencyAnalysis(input_bytes):
	# From https://en.wikipedia.org/wiki/Letter_frequency
    # with the exception of ' ', which I estimated.
    character_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }

    return sum([character_frequencies.get(chr(byte), 0) for byte in input_bytes.lower()])

def main():

	messageList = []
	cipherList = readFile()
	for cipher in cipherList:
		decodedCipher = bytes.fromhex(cipher)
		for key_value in range(127):
			message = singleCharXOR(decodedCipher,key_value)
			score = frequencyAnalysis(message)
			data = {
			'message': message,
			'score': score,
			#'cipher': cipher,
			'key':key_value
			}
			messageList.append(data)

	best_score = sorted(messageList, key=lambda x:x['score'], reverse=True)[0]
	print(best_score)






if __name__ == "__main__":
	main()