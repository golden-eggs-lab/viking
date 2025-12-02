import numpy as np
import pandas as pd
import time
import sys
import math
from multiprocessing import Barrier, Process, Lock, Event
from threading import BrokenBarrierError

# FedTopK Imports
from security.elgamal import ElGamal
from security.paillier import Paillier
from party import Party
from worker import Worker
from manager import get_ServerManager
from communication_helper import CommunicationEnvironment


# LOCAL implementation only

# Start time
start_time = time.time()

# Handle inputs (add partitioning scheme and security level...)
dataset          = sys.argv[1]
norm_type        = sys.argv[2]
query_weights_in = sys.argv[3]
k_in             = sys.argv[4]
num_parties      = int(sys.argv[5])
num_workers      = int(sys.argv[6])
partition_scheme = sys.argv[7]
security_level   = sys.argv[8]

# Check for and remove added comma
if ',' in k_in:
	k_in = k_in[:-1]

# Parse query weights
query_weights = []

for i in query_weights_in.split(', '):
	# print(i)
	query_weights.append(float(i))

# Initialize party inputs
num_participants    = num_parties + num_workers
role_numbers        = list(range(num_participants))

# Setup comm environment inputs
allAddresses    = []
roles           = []
address_root    = 'localhost'
party_root      = 2000
worker_root     = 3000
manager_root    = 4000

for part in role_numbers:
	if part < num_parties:
		add_tmp = (address_root, party_root + part)
		if part == 1:
			role_tmp = 'query_originator'
		else:
			role_tmp = 'party'
	elif part < num_participants:
		add_tmp = (address_root, worker_root + (part - num_parties))
		if part == num_parties:
			role_tmp = 'moderator'
		else:
			role_tmp = 'worker'

	allAddresses.append(add_tmp)
	roles.append(role_tmp)

# print('Initializing manager...')
add_tmp = (address_root, manager_root + (part - num_participants))
role_tmp = 'manager'
allAddresses.append(add_tmp)
roles.append(role_tmp)

# Initialize query
QueryWeights    = np.array(query_weights)
k               = int(k_in)

if security_level == 'secure':
	# Define security environment
	e_key_len   = 256                         # NIST recommended: 224  (160 for compare to SECYAN)
	e_bit_len   = 2048                        # NIST recommended: 2048 (1024 for compare to SECYAN)

	# Generate EG info for each worker
	eg_worker_info = []
	for w in range(num_workers):
		eg_worker_info.append(ElGamal(e_key_len, e_bit_len))

	if partition_scheme == 'vertical':
		# Add check on Paillier group length
		p_bit_len   = int(np.sqrt(np.sqrt(e_bit_len)))
		pa01        = Paillier(p_bit_len)
		count       = 0
		eg_p        = eg_worker_info[0].p

		while True:
			pa01.key_gen()
			pa_lim = pa01.usquare ** (num_parties + (3 * num_workers))
			# if __name__ == '__main__':
				# print('Encryption compare:\n' + 'Paillier usquare: ' + str(pa_lim) + '\n' + 'ElGamal p: ' + str(eg_p))
			if ((num_parties + (2 * num_workers)) * pa01.usquare) < eg_p:
				ratio01 = (num_parties + 1) * pa01.usquare / eg_p
				ratio02 = (pa01.usquare ** (num_parties + 1)) / eg_p
				break
			elif count == 10:
				break
			print('key gen count: ' + str(count))
			count += 1

# Initialize communication envrionment
lock = Lock()
CE   = CommunicationEnvironment(allAddresses, num_parties, num_workers, roles, lock)

# Specify data location and partitions
if norm_type == 'l1':
	if dataset == 'raisin':
		file_path = './data/processed/l1_raisin.csv'
	elif dataset == 'housing':
		file_path = './data/processed/l1_housing.csv'
	elif dataset == 'dry_bean':
		file_path = './data/processed/l1_drybean.csv'
	elif dataset == 'wine_quality':
		file_path = './data/processed/l1_winequality.csv'
	elif dataset == 'shuttle':
		file_path = './data/processed/l1_shuttle.csv'
elif norm_type == 'l2':
	if dataset == 'raisin':
		file_path = './data/processed/l2_raisin.csv'
	elif dataset == 'housing':
		file_path = './data/processed/l2_housing.csv'
	elif dataset == 'dry_bean':
		file_path = './data/processed/l2_drybean.csv'
	elif dataset == 'wine_quality':
		file_path = './data/processed/l2_winequality.csv'
	elif dataset == 'shuttle':
		file_path = './data/processed/l2_shuttle.csv'


# Check output top-k IDs
cols            = list(pd.read_csv(file_path, nrows = 1))
data_series_tmp = pd.read_csv(file_path)
# print(data_series_tmp.head())
data_series_tmp.index += 1
scores_tmp      = data_series_tmp * QueryWeights
db_len          = len(scores_tmp)

expected_scores = scores_tmp.sum(axis=1).sort_values(ascending=False)[:k]
expected_ids    = list(expected_scores.index)
expected_ids.reverse() # Sync order with algo return
if __name__ == '__main__':
	print(expected_scores)
	# print(expected_ids)

# Initialize parties (Inputs: Role number, role, partition scheme, communication environment)
PartyWorker_list    = []
eg_count            = 0
for role_num in range(num_participants):
	if role_num < num_parties:
		if role_num == 1:
			role_tmp = Party(role_numbers[role_num], roles[role_num], partition_scheme, security_level, CE, norm_type, QueryWeights, k, startTime = start_time, expected_answer=expected_ids)
		else:
			role_tmp = Party(role_numbers[role_num], roles[role_num], partition_scheme, security_level, CE, norm_type, startTime = start_time)
		if security_level == 'secure':
			role_tmp.set_pir_params(db_len, e_bit_len)
	else:
		# If statement really only applies in vertical case...
		if role_num == (num_participants - 1):
			if partition_scheme == 'horizontal':
				role_tmp = Worker(role_numbers[role_num], roles[role_num], partition_scheme, security_level, CE, eg_worker_info[eg_count], startTime = start_time)
			elif partition_scheme == 'vertical':
				# Include Paillier key at moderator in vertical setup
				if security_level == 'secure':
					role_tmp = Worker(role_numbers[role_num], roles[role_num], partition_scheme, security_level, CE, eg_worker_info[eg_count], pa01, startTime = start_time)
				elif security_level == 'nonsecure':
					role_tmp = Worker(role_numbers[role_num], roles[role_num], partition_scheme, security_level, CE, startTime = start_time)
		else:
			if security_level == 'secure':
				role_tmp = Worker(role_numbers[role_num], roles[role_num], partition_scheme, security_level, CE, eg_worker_info[eg_count], startTime = start_time)
			elif security_level == 'nonsecure':
				role_tmp = Worker(role_numbers[role_num], roles[role_num], partition_scheme, security_level, CE, startTime = start_time)
		eg_count += 1
	PartyWorker_list.append(role_tmp)

# Assign row numbers by party
db_row_nums = []
if partition_scheme == 'horizontal':
	dataset_tmp = pd.read_csv(file_path)
	num_rows_per_party  = math.floor(len(dataset_tmp) / num_parties)
	for party_num in range(num_parties):
		row_nums_tmp = list(range(party_num * num_rows_per_party, (party_num + 1) * num_rows_per_party))
		PartyWorker_list[party_num].ReadDataHorizontal(file_path, row_nums_tmp)
elif partition_scheme == 'vertical':
	for party_num in range(num_parties):
		PartyWorker_list[party_num].ReadDataVertical(file_path)

# Define function to run on each process
def TopK(PartyWorker):#, barrier, barrier2, barrier3, barrier4, event):
	PartyWorker.ProcessLoop()#barrier, barrier2, barrier3, barrier4, event)

def TopK_manage(address, num_parties, num_workers, role):
	manager = get_ServerManager(address, num_parties, num_workers, role)
	server  = manager.get_server()
	print('\n\n\n\n\n\nManager online: Serving forever')
	server.serve_forever()

# Entry point to processing
if __name__ == '__main__':
	# Create a barrier
	# barrier     = Barrier(num_participants) # All participants + main thread....
	# barrier2    = Barrier(num_participants)     # All participants
	# barrier3    = Barrier(num_participants - (num_workers - 1)) # All parties and one mixnet worker (moderator)
	# barrier4    = Barrier(num_parties)
	# event       = Event()
	jobs        = []

	# Start processes
	for i in range(num_participants + 1):
		if i < num_participants:
			# process = Process(target=TopK, args=(PartyWorker_list[i], barrier, barrier2, barrier3, barrier4, event, ), daemon=True)
			process = Process(target=TopK, args=(PartyWorker_list[i], )) #barrier, barrier2, barrier3, barrier4, event, ), daemon=True)
			process.start()
			jobs.append(process)
		else:
			process = Process(target=TopK_manage, args=(allAddresses[-1], num_parties, num_workers, roles[-1], ))
			process.start()
			jobs.append(process)

	job_count = 0
	for proc in jobs:
		if job_count != (len(jobs) - 1):
			proc.join()
		job_count += 1

	# End manager process
	jobs[-1].terminate()
	sys.exit()
	print("Exiting all child processess..\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n")

	# Wait for all processes to finish
	# try:
	# 	barrier.wait(timeout=5)
	# 	# barrier2.wait(timeout=5)
	# 	# print("Startup time: --- %s seconds ---" % (time.time() - start_time))
	# except BrokenBarrierError:
	# 	pass
	# 	# print('Some processes did not finish on time...')

	# while True:
	# 	if event.is_set():
	# 		print("Exiting all child processess..\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n")
	# 		for i in jobs:
	# 			#Terminate each process
	# 			i.terminate()
	# 		#Terminating main process
	# 		sys.exit(1)
	# 	time.sleep(2)



