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

		### Paillier
		# Inputs: (group_length)
		p_bit_len = 32

		# Paillier encryption scheme
		pa01 = Paillier(p_bit_len)
		pa01.key_gen()
		pkey01 = pa01.get_pkey()

		# Encrypt value with Paillier public key, then three separate ElGamal public keys
		# Happening on Party01 (for example)
		hash_ub 	= 10000 #int(pa01.u / 1000)
		value01 	= random.randint(0, hash_ub)+1
		value01 	= hash_ub
		value02 	= random.randint(0, 2000)+1
		value03 	= random.randint(0, 2000)+1
		value04 	= random.randint(0, 2000)+1
		rand_1 	= gmpy2.mpz_random(rand, eg01.g)
		rand_2 	= gmpy2.mpz_random(rand, eg01.g)
		print('Input value1: ' + str(value01))
		# print('Input value2: ' + str(value02))
		# print('Input value3: ' + str(value03))
		# print('Input value4: ' + str(value04))

		# Encrypt value with Paillier public key
		rp 	= pa01.gen_r()
		c01 = pa01.encrypt(value01)
		exp_num = 35 # Max total exponent: 214748 (32 bit limit), breaks down when final product > pa01.u
		# c_sum = c01 ** (exp_num) #* c02 * c03 * c04
		# print('Paillier encrypted product: ' + str(c_sum))
		# m_6 = gmpy2.powmod(c01, exp_num, pa01.usquare)
		# print('Paillier encrypted value2: ' + str(c02))

		# # Encrypt value using three workers' public keys (Party 1)
		gr, m_1 	= eg01.encrypt(c01, ekey01.k, rand_1)
		_ , m_2 	= eg02.encrypt(m_1, ekey02.k, rand_1)
		_ , m_3 	= eg03.encrypt(m_2, ekey03.k, rand_1)

		# # Encrypt value using three workers' public keys (Party 2)
		# gr2, m_12 	= eg01.encrypt(c02, ekey01.k, rand_2)
		# _ , m_22 	= eg02.encrypt(m_12, ekey02.k, rand_2)
		# _ , m_32	= eg03.encrypt(m_22, ekey03.k, rand_2)

		# # Encrypt value using three workers' public keys (Party 3)
		# gr3, m_13 	= eg01.encrypt(c03, ekey01.k, rand_2)
		# _ , m_23 	= eg02.encrypt(m_13, ekey02.k, rand_2)
		# _ , m_33	= eg03.encrypt(m_23, ekey03.k, rand_2)

		# # Encrypt value using three workers' public keys (Party 4)
		# gr4, m_14 	= eg01.encrypt(c04, ekey01.k, rand_2)
		# _ , m_24 	= eg02.encrypt(m_14, ekey02.k, rand_2)
		# _ , m_34	= eg03.encrypt(m_24, ekey03.k, rand_2)

		# Multiply encrypted values (to sum)
		gr_s, m_3s = gmpy2.powmod(gr, exp_num, eg02.p), gmpy2.powmod(m_3, exp_num, eg02.p) #(gr * gr2 * gr3 * gr4), (m_3 * m_32 * m_33 * m_34)
		# gr_s, m_3s = gmpy2.f_mod(gr_s, eg02.p), gmpy2.f_mod(m_3s, eg02.p)

		# gr_s2, m_3s2 = gr_s ** exp_num, m_3s ** exp_num #(gr * gr2 * gr3 * gr4), (m_3 * m_32 * m_33 * m_34)
		# gr_s2, m_3s2 = gmpy2.f_mod(gr_s2, eg02.p), gmpy2.f_mod(m_3s2, eg02.p)

		# gr_s, m_3s = gr_s2 ** exp_num, m_3s2 ** exp_num #(gr * gr2 * gr3 * gr4), (m_3 * m_32 * m_33 * m_34)
		# gr_s, m_3s = gmpy2.f_mod(gr_s, eg02.p), gmpy2.f_mod(m_3s, eg02.p)

		# gr_s, m_3s = gr_s * gr_s, m_3s * m_3s
		# gr_s, m_3s = gmpy2.f_mod(gr_s, eg02.p), gmpy2.f_mod(m_3s, eg02.p)

		# gr_s, m_3s = gr_s * gr_s, m_3s * m_3s
		# gr_s, m_3s = gmpy2.f_mod(gr_s, eg02.p), gmpy2.f_mod(m_3s, eg02.p)

		# Decrypt 1
		m_4 = eg01.decrypt(gr_s, m_3s)
		m_5 = eg02.decrypt(gr_s, m_4)
		m_6 = eg03.decrypt(gr_s, m_5)

		# Re-encrypt (add Paillier value)
		# mul_val_max = int(2e2) # int((pa01.u - hash_ub - 10) / 3)
		# mul_val01 = gmpy2.mpz_random(rand, mul_val_max) + 1
		# mul_val01 = mul_val_max
		# print('Mul value 01: ' + str(mul_val01))
		# # p_val01 = pa01.encrypt(add_val01)
		# grm4, m_4a 	= gmpy2.powmod(grm3, mul_val01, eg02.p), gmpy2.powmod(m_4, mul_val01, eg02.p)

		# p_enc = c01 ** (mul_val_max ** 3)
		# print('Bit len Paillier value: ' + str(c01.bit_length()))
		# print('Bit len Paillier cubed: ' + str(p_enc.bit_length()))
		# print('Bit len decrypt and multiply once: ' + str(m_4a.bit_length()))
		# print('Bit len p: ' + str(eg02.p.bit_length()))

		# Re-randomize
		# s_1 			= random.randint(0, eg01.p) + 1
		# gr_s1, m_s1 	= eg02.encrypt(1, ekey02.k, s_1)
		# _, m_s12 		= eg03.encrypt(m_s1, ekey03.k, s_1)
		# grm4, m_4 		= grm4 * gr_s1, m_4a * m_s12
		# grm4, m_4 		= gmpy2.f_mod(grm4, eg02.p), gmpy2.f_mod(m_4, eg02.p)

		# # Decrypt 2
		# m_5 = eg02.decrypt(grm4, m_4a)
		# # Re-encrypt 2
		# grm4, m_5a 	= gmpy2.powmod(grm4, mul_val01, eg02.p), gmpy2.powmod(m_5, mul_val01, eg02.p)

		# Re-encrypt (add Paillier value)
		# add_val_max = 10 # int((pa01.u - hash_ub - 10) / 3)
		# add_val02 = gmpy2.mpz_random(rand, add_val_max) + 1
		# print('Add value 02: ' + str(add_val02))
		# p_val02 = pa01.encrypt(add_val02)
		# m_5a 	= gmpy2.mul(m_5, p_val02)

		# Re-randomize
		# s_2 			= random.randint(0, eg02.p) + 1
		# gr_s2, m_s2 	= eg03.encrypt(1, ekey03.k, s_2)
		# grm5, m_5 		= grm3 * gr_s2, m_5a * m_s2
		# grm5, m_5 		= gmpy2.f_mod(grm5, eg03.p), gmpy2.f_mod(m_5, eg03.p)

		# # Decrypt 3
		# m_6 	= eg03.decrypt(grm4, m_5a)
		# # Re-encrypt 3
		# m_6a 	= gmpy2.powmod(m_6, mul_val01, eg02.p)

		# Re-encrypt (add Paillier value)
		# mul_val_max = int((pa01.u - hash_ub - 10) / 3)
		# add_val03 = gmpy2.mpz_random(rand, add_val_max) + 1
		# print('Add value 03: ' + str(add_val03))
		# p_val03 = pa01.encrypt(add_val03)
		# m_6a 	= gmpy2.mul(m_6, p_val03)

		# Decrypt Paillier layer
		m_1p, m_1pm = pa01.decrypt(m_6)
		print('Output value: ' + str(m_1p))
		print('Expected value: ' + str(value01 * (exp_num))) #+ value02 + value03 + value04)) #+ add_val01 + add_val02 + add_val03))
		# assert m_1p == (value01 + add_val01 + add_val02 + add_val03)
		break
	except Exception as e: 
		print(e)
		time.sleep(0.1)
	else:
		break
	try_count += 1
