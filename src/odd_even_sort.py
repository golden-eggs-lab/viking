from security.elgamal import ElGamal
import random
import gmpy2
import time
import numpy as np
from time import sleep

# HORIZONTAL algo only

rand = gmpy2.random_state(hash(gmpy2.random_state()))

def oddEvenSort(data):
	def swap(data, i, j):
		tmp = data[0, i]
		data[0, i] = data[0, j]
		data[0, j] = tmp

	# Sort status
	count = 0
	data_sorted = False
	while not data_sorted:
		data_sorted = True

		for i in range(1, data.size - 1, 2):
			# print('Loop 1: ' + str(i))
			if data[0, i] > data[0, i + 1]:
				count += 1
				# print('swap01')
				swap(data, i, i + 1)
				data_sorted = False
		for i in range(0, data.size - 1, 2):
			# print('Loop 2: ' + str(i))
			if data[0, i] > data[0, i + 1]:
				count += 1
				# print('swap02')
				swap(data, i, i + 1)
				data_sorted = False
	return data, count

d = np.random.randint(1000, size=(1,300))
d_sorted, count = oddEvenSort(d)
print(d_sorted)
print(count)



