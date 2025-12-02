from security.elgamal import ElGamal
from security.paillier import Paillier
import random
import gmpy2
import time
from pyecm import factors
import numpy as np

# Define random state
rand = gmpy2.random_state(hash(gmpy2.random_state()))

try_count = 0
while True:
	print('Try number: ' + str(try_count))
	try:
		### ElGamal
		# Inputs: (key_length, group_length)
		e_bit_len = 2048
		key_length = 224

		# First ElGamal Worker
		eg01 = ElGamal(key_length, e_bit_len)
		eg01.key_gen()
		ekey01 = eg01.get_ekey()

		# Second ElGamal Worker
		eg02 = ElGamal(key_length, e_bit_len)
		eg02.key_gen()
		ekey02 = eg02.get_ekey()

		# Third ElGamal Worker
		eg03 = ElGamal(key_length, e_bit_len)
		eg03.key_gen()
		ekey03 = eg03.get_ekey()

		# Values to compare
		val01 	= 1
		val02 	= 2

		# Encrypt value with three unique ElGamal public keys
		# Happening on Party01 (for example)
		rand01 	= gmpy2.mpz_random(rand, eg01.p)
		rand02	= gmpy2.mpz_random(rand, eg01.p)

		def EG_triple_enc(c01, eg01, eg02, eg03, ekey01, ekey02, ekey03, rand_1):
			# Encrypt value using three workers' public keys (Party 1)
			gr, m_1 	= eg01.encrypt(c01, ekey01.k, rand_1)
			_ , m_2 	= eg02.encrypt(m_1, ekey02.k, rand_1)
			_ , m_3 	= eg03.encrypt(m_2, ekey03.k, rand_1)

			return gr, m_3
		
		# Encrypt with three ElGamal keys
		gr01, m_01 	= EG_triple_enc(val01, eg01, eg02, eg03, ekey01, ekey02, ekey03, rand01)
		gr02, m_02 	= EG_triple_enc(val02, eg01, eg02, eg03, ekey01, ekey02, ekey03, rand02)

		# Invert m_02 and multiply
		gri_02, mi_02 	= gmpy2.invert(gr02, eg01.p), gmpy2.invert(m_02, eg01.p)
		grT_tmp, mT_tmp = gmpy2.mul(gr01, gri_02), gmpy2.mul(m_01, mi_02)
		grT, mT 		= gmpy2.f_mod(grT_tmp, eg01.p), gmpy2.f_mod(mT_tmp, eg01.p)

		# Decrypt ElGamal layer
		def EG_triple_dec(gr, v, eg01, eg02, eg03):
			m_4 = eg01.decrypt(gr, v)
			m_5 = eg02.decrypt(gr, m_4)
			m_6 = eg03.decrypt(gr, m_5)

			return m_6

		# Decrypt
		md_01 	= EG_triple_dec(grT, mT, eg01, eg02, eg03)
		# md_02 	= EG_triple_dec(gr02, m_02, eg01, eg02, eg03)
		print(md_01)
		break
	except Exception as e: 
		print(e)
		time.sleep(0.1)
	else:
		break
	try_count += 1
