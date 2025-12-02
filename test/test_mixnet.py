import unittest
import sys
import os
import gmpy2
import math

# Add src directory to path (match style of other tests)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from security.paillier import Paillier
from security.elgamal import ElGamal


def wrap_with_elgamal_layers(message_mpz, elgamal_keys, r_shared):
    """Encrypt a message under multiple ElGamal public keys with a shared r.

    Returns (gr, m) where gr = g^r mod p and m = message * prod(k_i^r) mod p
    """
    p = elgamal_keys[0].p
    gr, m = None, gmpy2.mpz(message_mpz)
    for eg in elgamal_keys:
        gr, m = eg.encrypt(m, eg.k, r_shared)
    return gr, m


def unwrap_elgamal_layers(gr, m, elgamal_keys):
    """Sequentially decrypt a multi-layer ElGamal ciphertext (gr, m)."""
    m_curr = gmpy2.mpz(m)
    for eg in elgamal_keys:
        m_curr = eg.decrypt(gr, m_curr)
    return m_curr


def multiply_elgamal_ciphertexts(c1, c2, p):
    """Component-wise multiply two ElGamal ciphertexts modulo p."""
    gr = gmpy2.f_mod(gmpy2.mul(c1[0], c2[0]), p)
    m = gmpy2.f_mod(gmpy2.mul(c1[1], c2[1]), p)
    return (gr, m)


def pow_elgamal_ciphertext(c, k, p):
    """Raise ElGamal ciphertext to scalar k modulo p (component-wise)."""
    gr_k = gmpy2.powmod(c[0], k, p)
    m_k = gmpy2.powmod(c[1], k, p)
    return (gr_k, m_k)


def multiply_many_elgamal_ciphertexts(cipher_list, p):
    gr = gmpy2.mpz(1)
    m = gmpy2.mpz(1)
    for c in cipher_list:
        gr = gmpy2.f_mod(gmpy2.mul(gr, c[0]), p)
        m  = gmpy2.f_mod(gmpy2.mul(m,  c[1]), p)
    return (gr, m)


class TestMixnetEncOperations(unittest.TestCase):
    def setUp(self):
        # Ensure ElGamal parameter files resolve relative to project root
        project_root = os.path.join(os.path.dirname(__file__), '..')
        os.chdir(project_root)
        tmp_sec_dir = os.path.join(project_root, 'src', 'tmp_security_parameters')
        os.makedirs(tmp_sec_dir, exist_ok=True)

        # Follow main.py sizing logic (scaled down for unit tests)
        num_parties = 3
        num_workers = 3
        self.e_key_len = 256          # scaled down from 224 for speed
        self.e_bit_len = 3072         # scaled down from 2048 for speed

        # Generate EG info for each worker
        self.eg1 = ElGamal(self.e_key_len, self.e_bit_len)
        self.eg1.key_gen()
        self.eg2 = ElGamal(self.e_key_len, self.e_bit_len)
        self.eg2.key_gen()
        self.eg3 = ElGamal(self.e_key_len, self.e_bit_len)
        self.eg3.key_gen()
        self.eg_keys = [self.eg1, self.eg2, self.eg3]

        eg_p = self.eg1.p

        # Paillier group length derived from sqrt(e_bit_len) as in main.py
        p_bit_len = 35
        print('p_bit_len = ' + str(p_bit_len))
        self.pa = Paillier(p_bit_len)

        count = 0
        while True:
            self.pa.key_gen()
            # Ensure relation: ((num_parties + 2*num_workers) * n^2) < p
            if ((num_parties + (2 * num_workers)) * self.pa.usquare) < eg_p:
                break
            elif count == 10:
                break
            count += 1

        # Sanity
        self.assertLess((num_parties + (2 * num_workers)) * self.pa.usquare, eg_p)



    def test_elgamal_wrapped_paillier_homomorphism(self):
        p = self.eg1.p
        n = self.pa.u
        n2 = self.pa.usquare

        # Two test values (include negative)
        values = [gmpy2.mpz(1), gmpy2.mpz(2), gmpy2.mpz(3), gmpy2.mpz(4), gmpy2.mpz(5), gmpy2.mpz(6), gmpy2.mpz(7), gmpy2.mpz(8)]

        C_list = []

        # Paillier encrypt each
        r_p = self.pa.gen_r(self.pa.get_pkey())
        ciphers = [self.pa.encrypt(v, self.pa.get_pkey(), r_p) for v in values]

        values_sum = sum(values)

        # Wrap under 3-layer ElGamal using shared r per ciphertext
        for c in ciphers:
            r_e = self.eg1.gen_r()
            C = wrap_with_elgamal_layers(c, self.eg_keys, r_e)
            C_list.append(C)

        # Homomorphic addition: component-wise multiply in ElGamal, then unwrap, then Paillier-decrypt
        Csum = multiply_many_elgamal_ciphertexts(C_list, p)
        csum_unwrapped = unwrap_elgamal_layers(Csum[0], Csum[1], self.eg_keys)
        csum_mod_n2 = gmpy2.f_mod(csum_unwrapped, n2)
        decrypted_sum, _ = self.pa.decrypt(csum_mod_n2)
        decrypted_sum = self.pa.smod(decrypted_sum, self.pa.get_pkey())
        print('decrypted_sum = ' + str(decrypted_sum))

        # expected_sum = self.pa.smod(gmpy2.f_mod(values_sum, n), self.pa.get_pkey())
        self.assertEqual(decrypted_sum, values_sum)

        # Scalar multiplication: raise wrapped ciphertext to k, unwrap, Paillier-decrypt
        k = 4
        C1k = pow_elgamal_ciphertext(Csum, k, p)
        c1k_unwrapped = unwrap_elgamal_layers(C1k[0], C1k[1], self.eg_keys)
        c1k_mod_n2 = gmpy2.f_mod(c1k_unwrapped, n2)
        decrypted_scalar, _ = self.pa.decrypt(c1k_unwrapped)
        print('decrypted_scalar = ' + str(decrypted_scalar))

        expected_scalar = self.pa.smod(gmpy2.f_mod(values_sum * k, n), self.pa.get_pkey())
        print('expected_scalar = ' + str(expected_scalar))
        self.assertEqual(decrypted_scalar, expected_scalar)

    def test_invert_equals_negation(self):
        p = self.eg1.p
        n = self.pa.u
        n2 = self.pa.usquare

        v = gmpy2.mpz(7)

        # Paillier encrypt
        r_p = self.pa.gen_r(self.pa.get_pkey())
        c = self.pa.encrypt(v, self.pa.get_pkey(), r_p)

        # Wrap under ElGamal (3 layers)
        r_e = self.eg1.gen_r()
        C = wrap_with_elgamal_layers(c, self.eg_keys, r_e)

        expected_neg = self.pa.smod(gmpy2.f_mod(-v, n), self.pa.get_pkey())

        # Optional (documented): component-wise inverse at ElGamal layer is not guaranteed
        # to correspond to Paillier inverse modulo n^2 after unwrap; we check and allow mismatch.
        C_inv_layer = (gmpy2.invert(C[0], n2), gmpy2.invert(C[1], n2))
        c_inv_layer_unwrapped = unwrap_elgamal_layers(C_inv_layer[0], C_inv_layer[1], self.eg_keys)
        # c_inv_layer_n2 = gmpy2.f_mod(c_inv_layer_unwrapped, n2)
        dec_layer, _ = self.pa.decrypt(c_inv_layer_unwrapped)
        dec_layer = self.pa.smod(dec_layer, self.pa.get_pkey())
        # This may or may not equal expected_neg depending on p and residues; assert nothing, but print for visibility
        # Use simple equality check for diagnostic runs
        self.assertEqual(dec_layer, expected_neg)


if __name__ == '__main__':
    unittest.main(verbosity=2)