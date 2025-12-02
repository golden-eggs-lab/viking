# Shared library
# from ctypes import *

# # lib_path = "/Users/jonald/Desktop/UMN_Masters_Schoolwork/2022Fall/DSCI_8760/FedTopK/FedTopK_Dev_working/pir_comm/SealPIR/src/CMakeFiles/main.dir/mainLib.so"
# lib_path = "/Users/jonald/Desktop/UMN_Masters_Schoolwork/2022Fall/DSCI_8760/FedTopK/FedTopK_Dev_working/test_so/MathLibrary.so"
# # print(open(lib_path))

# test = CDLL(lib_path)
# a = c_double(33322)
# b = c_double(6)
# c = c_double(1)
# out = test.Add(a, b, byref(c))
# print(type(out))
# print(out)

# print(c)



# # Subprocess (not good solution)
# import os
# cmd = '/Users/jonald/Desktop/UMN_Masters_Schoolwork/2022Fall/DSCI_8760/FedTopK/FedTopK_Dev_working/pir_comm/SealPIR/bin/main'
# so = os.popen(cmd).read()
# print(so)

from seal import *

# Input scheme_type
enc_params = EncryptionParameters(scheme_type.bfv)

# Input (optional) kswitchkeys
galois_keys = GaloisKeys()
print(galois_keys.get_index(0))