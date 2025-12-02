import random
from pathlib import Path
import gmpy2
from security.helper import str2int, float2int
from security.key import EKey
import os

rand = gmpy2.random_state(hash(gmpy2.random_state()))


class ElGamal:
    def __init__(self, key_length, group_length):
        # generate p and g, read from file if they exist
        code_dir = os.getcwd()
        p_path = f'{code_dir}/src/tmp_security_parameters/p_{group_length}.raw'
        p_file = Path(p_path)
        g_path = f'{code_dir}/src/tmp_security_parameters/g_{key_length}.raw'
        g_file = Path(g_path)
        print(f'g_file = {g_file} and p_file = {p_file}')

        if p_file.is_file() and g_file.is_file():
            self.p = gmpy2.from_binary(p_file.read_bytes())
            assert self.p.bit_length() == group_length
            self.g = gmpy2.from_binary(g_file.read_bytes())
            assert self.g.bit_length() == key_length
        else:
            p_len = 0
            while p_len != group_length:
                self.p = gmpy2.mpz_urandomb(rand, group_length)
                if gmpy2.is_prime(self.p):
                    p_len = self.p.bit_length()
            p_file.write_bytes(gmpy2.to_binary(self.p))

            g_len = 0
            while g_len != key_length:
                self.g = gmpy2.mpz_urandomb(rand, key_length)
                if gmpy2.is_prime(self.g):
                    g_len = self.g.bit_length()
            g_file.write_bytes(gmpy2.to_binary(self.g))
        # print('G: ' + str(self.g))
        # print('P: ' + str(self.p))
        self.clen = len(gmpy2.to_binary(self.p))
        self.x          = None
        self.k          = None
        self.inverse    = None
        self.exp        = None
        self.mpk        = None
        self.reenc_key  = None

    def key_gen(self):
        while True:
            self.x = self.gen_r()                           # Private key
            self.k = gmpy2.powmod(self.g, self.x, self.p)   # Public key
            # Make sure key length is exactly clen
            if len(gmpy2.to_binary(self.k)) == self.clen:
                break
        # Calculate inverse
        inverse         = gmpy2.sub(self.p, self.x)
        self.inverse    = gmpy2.sub(inverse, 1)
        self.exp        = gmpy2.add(self.x, 1)

        # Test enc/dec process
        self._test()

    def get_ekey(self):
        ekey = EKey()
        ekey.fill(self.x, self.k)
        return ekey

    def compute_mpk(self, ekeys):
        mpk = gmpy2.mpz(1)
        for ekey in ekeys:
            mpk = gmpy2.mul(mpk, ekey.k)
            mpk = gmpy2.f_mod(mpk, self.p)
        self.mpk = mpk

    def _test(self):
        # print(f'x= {self.x}\nk= {self.k}')

        v       = random.randint(0, 100000)
        gr, m   = self.encrypt(v, self.k)
        # print(f'gr= {gr}\nmgrx= {m}')

        re = self.decrypt(gr, m)
        # print(f'v= {v}\nre= {re}\n')
        assert v == re

    def gen_r(self):
        return gmpy2.mpz_random(rand, self.g)

    def encrypt(self, v, k, r=None):
        if r is None:
            r = self.gen_r()

        gr = gmpy2.powmod(self.g, r, self.p)
        # print(type(k), type(r), type(self.p))
        grx = gmpy2.powmod(k, r, self.p)
        # m = gmpy2.mul(v, grx)
        m = v * grx

        m = gmpy2.f_mod(m, self.p)

        return gr, m

    def decrypt(self, gr, m):
        re = gmpy2.powmod(gr, self.inverse, self.p)
        re = gmpy2.mul(re, m)
        re = gmpy2.f_mod(re, self.p)

        return re

    def encrypt_tid(self, inputs):
        # each party encrypts tid value by its own public key
        tid = inputs[0]
        r = inputs[1]
        cipher = self.encrypt(tid, self.k, r)

        return (cipher[0], cipher[1], r)

    def encrypt_attr_eq(self, inputs):
        # each party encrypts the value with equality using all workers' pubkey
        v = inputs[0]
        r = inputs[1]
        if isinstance(v, str):
            v = str2int(v)
        elif isinstance(v, float):
            v = float2int(v)

        return self.encrypt(v, self.mpk, r)

    def draw_reenckey(self):
        self.reenc_key = self.gen_r()

    def reecnrypted_tid(self, tid):
        c1, c2  = tid[0], tid[1]
        c1_xj   = gmpy2.powmod(c1, self.x, self.p)
        c2      = gmpy2.mul(c2, c1_xj)
        c2      = gmpy2.f_mod(c2, self.p)

        return (c1, c2)

    def reencrypt_attr_eq(self, inputs):
        v       = inputs[0]
        c1, c2  = v[0], v[1]
        c2      = self.decrypt(c1, c2)
        # re-enc c1, c2
        c1      = gmpy2.powmod(c1, self.reenc_key, self.p)
        c2      = gmpy2.powmod(c2, self.reenc_key, self.p)
        # re-rand
        s       = inputs[1]
        gs      = gmpy2.powmod(self.g, s, self.p)
        c1      = gmpy2.mul(c1, gs)
        c1      = gmpy2.f_mod(c1, self.p)
        gsk     = gmpy2.powmod(self.mpk, s, self.p)
        c2      = gmpy2.mul(c2, gsk)
        c2      = gmpy2.f_mod(c2, self.p)

        return (c1, c2)

    def decrypt_attr_ord(self, inputs):
        c1, c2 = inputs[0], inputs[1]
        c2 = self.decrypt(c1, c2)
        return (c1, c2)

    def mul(self, grad_per_loc):
        # merge all locations in idx from all grad_list
        gr = 1
        m = 1

        for grads in grad_per_loc:

            pgr = grads[0]
            pm = grads[1]

            gr = gmpy2.mul(gr, pgr)
            gr = gmpy2.f_mod(gr, self.p)

            m = gmpy2.mul(m, pm)
            m = gmpy2.f_mod(m, self.p)

        return (gr, m)

    def derand(self, inputs):
        # decrypt and re-random gradients
        grad = inputs[0]
        gr, m = grad[0], grad[1]
        r = inputs[1]

        m = self.decrypt(gr, m)

        gr_prime = gmpy2.powmod(self.g, r, self.p)
        gr = gmpy2.mul(gr, gr_prime)
        gr = gmpy2.f_mod(gr, self.p)

        grmpk = gmpy2.powmod(self.mpk, r, self.p)
        m = gmpy2.mul(m, grmpk)
        m = gmpy2.f_mod(m, self.p)

        return (gr, m)

    def encrypt_encoding(self, encoding):
        rs = encoding.rs
        pos = 0

        for zero in encoding.zeros:
            enc_zero = self.encrypt(zero, self.mpk, rs[pos])
            encoding.enc_zeros.append(enc_zero)
            pos += 1

        for one in encoding.ones:
            enc_one = self.encrypt(one, self.mpk, rs[pos])
            encoding.enc_ones.append(enc_one)
            pos += 1

        assert pos == len(rs)

        return encoding

    def reencrypt_encoding(self, encoding):
        new_zeros = []
        for ec in encoding.enc_zeros:
            r = self.gen_r()
            ec = self.reencrypt_attr_eq((ec, r))
            new_zeros.append(ec)
        new_ones = []
        for ec in encoding.enc_ones:
            r = self.gen_r()
            ec = self.reencrypt_attr_eq((ec, r))
            new_ones.append(ec)

        encoding.enc_zeros = new_zeros
        encoding.enc_ones = new_ones

