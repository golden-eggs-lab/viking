import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

import pickle
import time
from bit_compare import Encoding
from worker import Worker, setupWorker
from party import Party, setupParty
# from mixnet_helper import Mixnet
import numpy as np
from multiprocessing import Pool
from matplotlib import pyplot as plt


def unitTestWorker():
	# Time operations
	start_time = time.time()

	# Parallel test
	parallel = False

	def test(jj):
		print(jj)

	input_file_name = './pir_encrypt_database_input'
	with open(input_file_name, 'rb') as f:
		test_worker_attr = pickle.load(f)

	# Party attributes needed in ComaprativeMixnetID
	load_attr 	= ['ElGamalInfo', 'ID_store', 'ElGamalPubKeys']
	worker_test = setupWorker(True)

	worker_test.lock 			= None
	worker_test.ElGamalInfo 	= test_worker_attr[load_attr[0]]
	worker_test.ID_store 		= test_worker_attr[load_attr[1]]
	worker_test.ElGamalPubKeys 	= test_worker_attr[load_attr[2]]

	# Parallel test hook
	if parallel:
		if __name__ == '__main__':
			num_procs = len(test_worker_attr['Data'])
			print(test_worker_attr['Data'])
			print('Number of stored IDs: ' + str(len(worker_test.ID_store)))
			# print('Parallel input length: ' + str(len(test_worker_attr['Data'])))
			# num_procs 	= os.cpu_count() - 1
			with Pool(processes=num_procs) as w_pool:
				print('Num procs = ' + str(num_procs))
				multiple_results = [w_pool.apply_async(worker_test.ComparativeMixnetID,
										args=([test_worker_attr['Data'][i]],)) for i in range(num_procs)]
				
				# for x in multiple_results:
				# 	print(x._items)
				# multiple_results = [w_pool.apply_async(os.getpid, ()) for i in range(num_procs)]
				# print(multiple_results)
				mixnet_output = []
				for res in multiple_results:
					res_tmp = res.get(timeout=3)
					mixnet_output.append(res_tmp[0])
					# print('Res len: ' + str(len(res_tmp[0])))
					# print(res_tmp)
					# print('\n\n\n\n\n')

				w_pool.close() # Probably don't want this in protocol..?
	else:
		mixnet_output = worker_test.ComparativeMixnetID(test_worker_attr['Data'])

	if __name__ == '__main__':
		ID_included = []
		for ID_check in mixnet_output:
			for obj in ID_check:
				includeFlag 	= False
				includeDouble 	= 0
				for ID_check_check in test_worker_attr['Processed Data']:
					for obj_check in ID_check_check:
						if obj.ID == obj_check.ID:
							if includeDouble == 0:
								includeFlag = True
							else:
								includeFlag = False
							includeDouble += 1
				ID_included.append(includeFlag)
		passFlag = np.all(ID_included)
		if passFlag:
			print('PASS, Comparitive Mixnet...')
		else:
			print('FAIL, Comparitive Mixnet...')

		# Output run time
		run_time = time.time() - start_time
		print('Total runtime: ' + str(run_time))


def unitTestParty():
	# Time operations
	start_time = time.time()

	# Parallel test
	parallel = True

	def test(jj):
		print(jj)

	input_file_name = './unit_test_party_input'
	with open(input_file_name, 'rb') as f:
		test_worker_attr = pickle.load(f)

	# Party attributes needed in ComaprativeMixnetID
	load_attr 	= ['PaillierPubKeys', 'ElGamalInfo', 'ElGamalPubKeys']
	party_test 	= setupParty(True)
	party_test.CalculateScores()

	party_test.lock 			= None
	party_test.PaillierPubKeys  = test_worker_attr[load_attr[0]]
	party_test.ElGamalInfo 		= test_worker_attr[load_attr[1]]
	party_test.ElGamalPubKeys 	= test_worker_attr[load_attr[2]]

	# Parallel test hook
	if parallel:
		if __name__ == '__main__':
			num_procs 	= os.cpu_count() - 1
			with Pool(processes=num_procs) as w_pool:
				# print('Num procs = ' + str(num_procs))
				total_database 	= party_test.scoresOT.astype('int')
				db_len 			= len(total_database)
				print('Len db: ' + str(db_len))
				db_spl_ind 	= int(db_len / num_procs)
				test_input  = []
				inds 		= list(np.arange(num_procs) * db_spl_ind)
				inds.append(db_len)
				print('inds: ' + str(inds))
				for p in range(num_procs):
					db_iter = total_database[inds[p]:inds[p+1]]
					print(db_iter)
					test_input.append(db_iter)
					# print('Iter: ' + str(p))
					# print('start of db : ' + str(db_iter[:10]))
					# print('end of db: ' + str(db_iter[-10:]))
				print('test_input' + str(test_input))
				multiple_results = w_pool.imap(party_test.pir_encrypt_database, test_input)

				# for x in multiple_results:
				# 	print(x._items)
				# multiple_results = [w_pool.apply_async(os.getpid, ()) for i in range(num_procs)]
				# print(multiple_results)
				mixnet_output = []
				multiple_results_count = 0
				for res in multiple_results:
					print('multiple_results_count' + str(multiple_results_count))
					print(res[:10])
					for ress in res:
						res_tmp = ress #.get(timeout=3)
						# print(res_tmp, res_tmp[0])
						mixnet_output.append(res_tmp)
					# print('Res len: ' + str(len(res_tmp[0])))
					# print(res_tmp)
					# print('\n\n\n\n\n')
				out_len = len(mixnet_output)
				# print('Output length: ' + str(out_len))
				# print(mixnet_output)
				w_pool.close() # Probably don't want this in protocol..?
	# else:
	# 	mixnet_output = worker_test.ComparativeMixnetID(test_worker_attr['Data'])

	# if __name__ == '__main__':
	# 	ID_included = []
	# 	for ID_check in mixnet_output:
	# 		for obj in ID_check:
	# 			includeFlag 	= False
	# 			includeDouble 	= 0
	# 			for ID_check_check in test_worker_attr['Processed Data']:
	# 				for obj_check in ID_check_check:
	# 					if obj.ID == obj_check.ID:
	# 						if includeDouble == 0:
	# 							includeFlag = True
	# 						else:
	# 							includeFlag = False
	# 						includeDouble += 1
	# 			ID_included.append(includeFlag)
	# 	passFlag = np.all(ID_included)
	if test_worker_attr['Expected Output'] == mixnet_output:
		passFlag = True
	else:
		passFlag = False
		# result = test_worker_attr['Expected Output'] == mixnet_output
		expected = test_worker_attr['Expected Output']
		actual 	= mixnet_output
		result = np.sum(actual) == np.sum(expected)
		print('result' + str(result))
		# plt.plot(result)
		# plt.show()
		test_ind_start 	= 1398 * 512
		test_ind_end 	= 1399 * 512
		print('Len expected: ' + str(len(test_worker_attr['Expected Output'])))
		print(str(test_worker_attr['Expected Output'][test_ind_start:test_ind_end]))
		print('\n\n\nLen output: ' + str(len(mixnet_output)))
		print(str(mixnet_output[test_ind_start:test_ind_end]))
	if passFlag:
		print('PASS, DB PIR...')
	else:
		print('FAIL, DB PIR...')

		# Output run time
		# if __name__ == '__main__':
		run_time = time.time() - start_time
		print('Total runtime: ' + str(run_time))

# Enter main
if __name__ == '__main__':
	unitTestWorker()
	unitTestParty()


