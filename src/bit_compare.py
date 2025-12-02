from security.elgamal import ElGamal
import gmpy2
import time
from time import sleep

# HORIZONTAL Algorithm only

rand 	= gmpy2.random_state(hash(gmpy2.random_state()))
# max_int = gmpy2.mpz(2**64 - 1)

class Encoding():
	def __init__(self):
		pass

	def addLeadingZeros(self, binary_str, expected_byte_len):
		binary_str = binary_str	 			 	# Remove two leading values (not in the binary representation)
		str_len = len(binary_str)
		if str_len < expected_byte_len:
			# Add leading zeros
			leadingZeros = '0' * (expected_byte_len - str_len)
			outputBinaryString = leadingZeros + binary_str
		else:
			outputBinaryString = binary_str
		return outputBinaryString

	def calcZeroEncoding(self, number, byte_length):
		binaryNumber 		= bin(number)[2:]  		# Remove two leading values (not in the binary representation)
		fullBinaryNumber 	= self.Encoding.addLeadingZeros(binaryNumber, byte_length)
		binaryLength 		= len(fullBinaryNumber)
		setZeroEncoding 	= []
		max_int 			= gmpy2.mpz(2**byte_length - 1)
		for byteInd in range(binaryLength):
			ind_tmp		= binaryLength - byteInd - 1
			byte_tmp 	= fullBinaryNumber[ind_tmp]
			if byte_tmp == '0':
				zeroEncoding_tmp 	= fullBinaryNumber[:ind_tmp] + '1'
				zeroEncodingInt 	= int(zeroEncoding_tmp, 2)
				setZeroEncoding.append(zeroEncodingInt)
			else:
				r_tmp 	= gmpy2.mpz_random(rand, max_int)
				setZeroEncoding.append(r_tmp)
		return setZeroEncoding

	def calcOneEncoding(self, number, byte_length):
		binaryNumber 		= bin(number)[2:]  		# Remove two leading values (not in the binary representation)
		fullBinaryNumber 	= self.Encoding.addLeadingZeros(binaryNumber, byte_length)
		binaryLength 		= len(fullBinaryNumber)
		setOneEncoding	 	= []
		max_int = gmpy2.mpz(2**byte_length - 1)
		for byteInd in range(binaryLength):
			ind_tmp		= binaryLength - byteInd - 1
			byte_tmp 	= fullBinaryNumber[ind_tmp]
			if byte_tmp == '1':
				zeroEncoding_tmp = fullBinaryNumber[:ind_tmp + 1]
				zeroEncodingInt 	= int(zeroEncoding_tmp, 2)
				setOneEncoding.append(zeroEncodingInt)
			else:
				r_tmp 	= gmpy2.mpz_random(rand, max_int)
				setOneEncoding.append(r_tmp)
		return setOneEncoding
