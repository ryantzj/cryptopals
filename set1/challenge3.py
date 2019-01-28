

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
	ciphertext= bytes.fromhex(string)
	messageList = []
	for key_value in range(127):
		message = singleCharXOR(ciphertext,key_value)
		score = frequencyAnalysis(message)

		data = {
			'message': message,
			'score': score,
			'key':key_value
		}
		messageList.append(data)

	best_score = sorted(messageList, key=lambda x:x['score'], reverse=True)
	print(best_score)
	#for item in best_score:
	#	print("{}: {}".format(item.title(), best_score[item]))



if __name__ == "__main__":
	main()
