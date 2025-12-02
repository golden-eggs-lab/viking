from security.elgamal import ElGamal
from security.paillier import Paillier
import random
import gmpy2
import time

# Define random state
rand = gmpy2.random_state(hash(gmpy2.random_state()))

try_count = 0
while True:
	print('Try number: ' + str(try_count))
	try:
		### ElGamal
		# Inputs: (key_length, group_length)
		e_bit_len = 256 #1032

		# First ElGamal Worker
		eg01 = ElGamal(e_bit_len, e_bit_len)
		eg01.key_gen()
		ekey01 = eg01.get_ekey()

		# Second ElGamal Worker
		eg02 = ElGamal(e_bit_len, e_bit_len)
		eg02.key_gen()
		ekey02 = eg02.get_ekey()

		# Third ElGamal Worker
		eg03 = ElGamal(e_bit_len, e_bit_len)
		eg03.key_gen()
		ekey03 = eg03.get_ekey()

		# Encrypt value with three separate ElGamal public keys
		# Happening on Party01 (for example)
		hash_ub 	= int(1e6)
		value01 	= random.randint(0, hash_ub)+1
		# value02 = random.randint(0, 25000)
		rand_1 	= gmpy2.mpz_random(rand, eg01.g)
		print('Input value: ' + str(value01))

		# Encrypt value using three workers' public keys
		gr, m_1 = eg01.encrypt(value01, ekey01.k, rand_1)
		_, m_2 	= eg02.encrypt(m_1, ekey02.k, rand_1)
		_, m_3 	= eg03.encrypt(m_2, ekey03.k, rand_1)

		# Decrypt 1
		grm3 = gr
		m_4 = eg01.decrypt(grm3, m_3)

		# Re-encrypt (exponentiate x')
		# eg01a = ElGamal(e_bit_len, e_bit_len)
		# eg01a.key_gen()
		# ekey01a = eg01a.get_ekey()
		sk_2    		= gmpy2.mpz_random(rand, eg01.p) + 1
		gr_sk, m4_sk  	= gmpy2.powmod(grm3, sk_2, eg01.p), gmpy2.powmod(m_4, sk_2, eg01.p)
		# m_4r 			= m_4 * gr_x
		# m_4r 			= gmpy2.f_mod(m_4r, eg01a.p)

		# # Re-randomize (changes g^r...)
		# s_1 			= random.randint(0, eg01a.p) + 1
		# # Use public keys that value is currently encrypted with to encrypt value of 1
		# gr_s1, m_s1 	= eg02.encrypt(1, ekey02.k, s_1)
		# _, m_s12 		= eg03.encrypt(m_s1, ekey03.k, s_1)
		# # Use refresh encryption value
		# gr_xa		  	= gmpy2.powmod(gr_s1, ekey01a.x, eg01a.p)
		# m_s12a 			= gmpy2.f_mod(m_s12 * gr_xa, eg01a.p)
		# grm3, m_4 		= grm3 * gr_s1, m_4r * m_s12a
		# grm3, m_4 		= gmpy2.f_mod(grm3, eg01.p), gmpy2.f_mod(m_4, eg01.p)

		# Decrypt 2
		m_5 = eg02.decrypt(gr_sk, m4_sk)

		# Refresh by exponentiating g^r ^x (EG 2)
		# eg02a = ElGamal(e_bit_len, e_bit_len)
		# eg02a.key_gen()
		# ekey02a = eg02a.get_ekey()
		# gr_x  	= gmpy2.powmod(grm3, ekey02a.x, eg02a.p)
		# m_5r 	= m_5 * gr_x
		# m_5r 	= gmpy2.f_mod(m_5r, eg02a.p)

		# Re-randomize (changes g^r...)
		# s_2 			= random.randint(0, eg02.p) + 1
		# gr_s2, m_s2 	= eg03.encrypt(1, ekey03.k, s_2)
		# grm5, m_5 		= grm3 * gr_s2, m_5 * m_s2
		# grm5, m_5 		= gmpy2.f_mod(grm5, eg03.p), gmpy2.f_mod(m_5, eg03.p)
		# s_2 			= random.randint(0, eg02a.p) + 1
		# _, m_s22 		= eg03.encrypt(1, ekey03.k, s_2)
		# # Use refresh encryption value (1)
		# gr_xa		  	= gmpy2.powmod(gr_s1, ekey01a.x, eg01a.p)
		# m_s12a 			= gmpy2.f_mod(m_s22 * gr_xa, eg01a.p)
		# grm3, m_4 		= grm3 * gr_s1, m_4r * m_s12a
		# grm3, m_4 		= gmpy2.f_mod(grm3, eg01.p), gmpy2.f_mod(m_4, eg01.p)
		# # Use refresh encryption value (2)
		# gr_xa		  	= gmpy2.powmod(gr_s1, ekey01a.x, eg01a.p)
		# m_s12a 			= gmpy2.f_mod(m_s12 * gr_xa, eg01a.p)
		# grm3, m_4 		= grm3 * gr_s1, m_4r * m_s12a
		# grm3, m_4 		= gmpy2.f_mod(grm3, eg01.p), gmpy2.f_mod(m_4, eg01.p)

		# Decrypt 3
		m_6 = eg03.decrypt(gr_sk, m_5)

		# Refresh by exponentiating g^r ^x (EG 3)
		# eg03a = ElGamal(e_bit_len, e_bit_len)
		# eg03a.key_gen()
		# ekey03a = eg03a.get_ekey()
		# gr_x  	= gmpy2.powmod(grm3, ekey03a.x, eg03a.p)
		# m_6r 	= m_6 * gr_x
		# m_6r 	= gmpy2.f_mod(m_6r, eg03a.p)

		# Decrypt 1a
		# m_7 = eg01a.decrypt(grm3, m_6r)
		# m_8 = eg02a.decrypt(grm3, m_7)
		# m_9 = eg03a.decrypt(grm3, m_8)
		print('Output value: ' + str(m_6))
		print('Expected value: ' + str(value01))
		# assert m_6 == (value01)
		break
	except Exception as e: 
		print(e)
		time.sleep(0.1)
	else:
		break
	try_count += 1
