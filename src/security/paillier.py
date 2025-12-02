import random
import gmpy2
from security.key import PKey

# Initialize random state
rand = gmpy2.random_state(hash(gmpy2.random_state()))


def getprimeover(N):
    # Iterate through primes with input bit length
    randfunc = random.SystemRandom()
    r = gmpy2.mpz(randfunc.getrandbits(N))
    r = gmpy2.bit_set(r, N - 1)
    return gmpy2.next_prime(r)


class Paillier:
    def __init__(self, group_length):
        self.group_length   = group_length
        self.u              = None
        self.usquare        = None
        self.s              = None
        self.lam            = None
        self.mu             = None
        self.pkey           = PKey()

    def key_gen(self):
        # public key is (u, s)
        u_len = 0
        while u_len != self.group_length:
            p1_len  = self.group_length // 2
            p2_len  = self.group_length - p1_len
            p1      = getprimeover(p1_len)
            p2      = p1
            while p2 == p1:
                p2  = getprimeover(p2_len)
            # print('p1: ' + str(p1), 'p2: ' + str(p2))
            self.u = gmpy2.mul(p1, p2)
            # print('u: ' + str(self.u))
            u_len  = self.u.bit_length()

        self.usquare = gmpy2.mpz(gmpy2.mul(self.u, self.u))
        self.s = self.u + 1
        # print('usquare: ' + str(self.usquare))
        # private key is (lam, mu)
        self.lam = gmpy2.mul(p1-1, p2-1)
        self.mu = gmpy2.invert(self.lam, self.u)
        self.pkey.fill(self.u, self.s)

        self._test()

    def set_pkey(self, pkey):
        self.pkey = pkey

    def get_pkey(self):
        return self.pkey

    def smod(self, v, pkey):
        n = pkey.u

        if v >= n // 2:
            return v - n
        else:
            return v

    def encrypt(self, v, pkey=None, r=None):
        if pkey is None:
            pkey = self.pkey
        if r is None:
            r = self.gen_r()
        # v = self.smod(v, pkey)
        # print(type(pkey.s), type(v), type(pkey.usquare))
        sv      = gmpy2.powmod(pkey.s, v, pkey.usquare)
        ru      = gmpy2.powmod(r, pkey.u, pkey.usquare)
        c_mult  = gmpy2.mul(sv, ru)
        c       = gmpy2.f_mod(c_mult, pkey.usquare)
        return c

    def decrypt(self, c):
        l_input         = gmpy2.powmod(c, self.lam, self.usquare)
        l_output        = gmpy2.div(l_input - 1, self.u)
        l_output_conv   = gmpy2.mpz(l_output)                 # ADDITION (typing error)
        re_pre_mod      = gmpy2.mul(l_output_conv, self.mu)
        re              = gmpy2.f_mod(re_pre_mod, self.u)

        re = self.smod(re, self.pkey)
        return re, re_pre_mod

    def gen_r(self, pkey=None):
        if pkey is None:
            pkey = self.pkey
        while True:
            r = gmpy2.mpz_random(rand, pkey.u)
            ru_gcd = gmpy2.gcd(r, pkey.u)
            # print('ru GCD: ' + str(ru_gcd))
            if ru_gcd == 1:
                break
        return r

    def enc0(self):
        return self.encrypt(0)

    def _test(self):
        v1 = random.randint(0, self.u) # ADDITION (range of m or v1 in this case)
        c1 = self.encrypt(v1)
        re1, re1_pm= self.decrypt(c1)
        v1 = self.smod(v1, self.pkey)

        assert v1 == re1

        v2 = random.randint(0, self.u) # ADDITION (range of m or v1 in this case)
        c2 = self.encrypt(v2)
        c = gmpy2.mul(c1, c2)
        c = gmpy2.f_mod(c, self.usquare)
        re, re_pm = self.decrypt(c)

        vs = gmpy2.f_mod(v1+v2, self.u)
        vs = self.smod(vs, self.pkey)
        # print(f'{vs == re}')
        assert vs == re

        # print(f'Paillier testing pass: {v1 == re1}\t{vs == re}')

    def encrypt_grad(self, inputs):
        v = inputs[0]
        r = inputs[1]

        return self.encrypt(v, self.pkey, r)

    def decrypt_grad(self, grad):
        gr, m = grad[0], grad[1]
        m = gmpy2.f_mod(m, self.usquare)
        v, v_pm = self.decrypt(m)

        return (gr, v)


