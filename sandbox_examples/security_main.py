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
		e_bit_len = 256 #1024

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

		### Paillier
		# Inputs: (group_length)
		p_bit_len = 16 #32

		# Paillier encryption scheme
		pa01 = Paillier(p_bit_len)
		pa01.key_gen()
		pkey01 = pa01.get_pkey()

		# Encrypt value with Paillier public key, then three separate ElGamal public keys
		# Happening on Party01 (for example)
		hash_ub 	= int(pa01.u / 10)
		value01 	= random.randint(0, hash_ub)+1
		# value02 = random.randint(0, 25000)
		rand_1 	= gmpy2.mpz_random(rand, eg01.g)
		print('Input value: ' + str(value01))
		# print('Input value2: ' + str(value02))

		# Encrypt value with Paillier public key
		c01 = pa01.encrypt(value01)
		print('Paillier encrypted value: ' + str(c01))

		# Encrypt value using three workers' public keys
		gr, m_1 = eg01.encrypt(c01, ekey01.k, rand_1)
		_, m_2 	= eg02.encrypt(m_1, ekey02.k, rand_1)
		_, m_3 	= eg03.encrypt(m_2, ekey03.k, rand_1)

		# Decrypt 1
		grm3 = gr
		m_4 = eg01.decrypt(grm3, m_3)

		# Re-encrypt (add Paillier value)
		add_val_max = int((pa01.u - hash_ub - 10) / 3)
		add_val01 = gmpy2.mpz_random(rand, add_val_max) + 1
		print('Add value 01: ' + str(add_val01))
		p_val01 = pa01.encrypt(add_val01)
		m_4a 	= gmpy2.mul(m_4, p_val01)

		# Re-randomize
		s_1 			= random.randint(0, eg01.p) + 1
		gr_s1, m_s1 	= eg02.encrypt(1, ekey02.k, s_1)
		_, m_s12 		= eg03.encrypt(m_s1, ekey03.k, s_1)
		grm3, m_4 		= grm3 * gr_s1, m_4a * m_s12
		grm3, m_4 		= gmpy2.f_mod(grm3, eg01.p), gmpy2.f_mod(m_4, eg01.p)

		# Decrypt 2
		m_5 = eg02.decrypt(grm3, m_4)

		# Re-encrypt (add Paillier value)
		add_val_max = int((pa01.u - hash_ub - 10) / 3)
		add_val02 = gmpy2.mpz_random(rand, add_val_max) + 1
		print('Add value 02: ' + str(add_val02))
		p_val02 = pa01.encrypt(add_val02)
		m_5a 	= gmpy2.mul(m_5, p_val02)

		# Re-randomize
		s_2 			= random.randint(0, eg02.p) + 1
		gr_s2, m_s2 	= eg03.encrypt(1, ekey03.k, s_2)
		grm5, m_5 		= grm3 * gr_s2, m_5a * m_s2
		grm5, m_5 		= gmpy2.f_mod(grm5, eg03.p), gmpy2.f_mod(m_5, eg03.p)

		# Decrypt 3
		m_6 = eg03.decrypt(grm5, m_5)

		# Re-encrypt (add Paillier value)
		add_val_max = int((pa01.u - hash_ub - 10) / 3)
		add_val03 = gmpy2.mpz_random(rand, add_val_max) + 1
		print('Add value 03: ' + str(add_val03))
		p_val03 = pa01.encrypt(add_val03 + pa01.u - 5)
		m_6a 	= gmpy2.mul(m_6, p_val03)

		# Decrypt Paillier layer
		m_1p, m_1pm = pa01.decrypt(m_6a)
		print('Output value: ' + str(m_1p))
		print('Expected value: ' + str(value01 + add_val01 + add_val02 + add_val03))
		# assert m_1p == (value01 + add_val01 + add_val02 + add_val03)
		break
	except Exception as e: 
		print(e)
		time.sleep(0.1)
	else:
		break
	try_count += 1




