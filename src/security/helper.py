import glob
import hashlib


# hash a floating number to integer by keep two points
def float2int(f):
    return int(f*100)


# a factor to map gradient to int
grad4factor = 100000

def str2int(s):
    return int(hashlib.sha1(s.encode("utf-8")).hexdigest(), 16) % (10 ** 8)
