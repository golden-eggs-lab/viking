import gmpy2


class EKey:
    def __init__(self):
        self.x = None
        self.k = None
        self.bk = None

    def fillb(self, bk):
        self.bk = bk
        self.k = gmpy2.from_binary(bk)

    def fill(self, x, k):
        self.x  = x
        self.k  = k
        self.bk = gmpy2.to_binary(k)


class PKey:
    def __init__(self):
        self.u = None
        self.s = None
        self.bu = None
        self.bs = None
        self.usquare = None

    def fill(self, u, s):
        self.u = u
        self.s = s
        self.bu = gmpy2.to_binary(u)
        self.bs = gmpy2.to_binary(s)

        self.usquare = gmpy2.mpz(gmpy2.mul(u, u))

    def fillb(self, bu, bs):
        self.bu = bu
        self.bs = bs
        self.u = gmpy2.from_binary(bu)
        self.s = gmpy2.from_binary(bs)

        self.usquare = gmpy2.mpz(gmpy2.mul(self.u, self.u))
