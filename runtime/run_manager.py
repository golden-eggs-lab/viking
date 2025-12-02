from multiprocessing.managers import SyncManager
from multiprocessing import Process, Barrier, Event, Queue
import time
import sys
import os

# FedTopK imports
working_dir = os.getcwd()
src_dir = f"{working_dir}/src"
sys.path.append(src_dir)
from manager import get_ServerManager
from worker import paillier_send, elgamal_send
from party import EntryStorage

# Start time
start_time = time.time()

try:
	# Handle inputs (add partitioning scheme and security level...)
	# dataset          = sys.argv[1]
	# query_weights_in = sys.argv[2]
	# k_in             = sys.argv[3]
	num_parties      = int(sys.argv[1])
	num_workers      = int(sys.argv[2])
	# partition_scheme = sys.argv[6]
	# security_level   = sys.argv[7]
	role_number      = int(sys.argv[3])
	address_list 	 = sys.argv[4]
	print(address_list)
	print('Manager set using inputs...')
except:
	print('Manager using default inputs...')
	# dataset          = 'wine_quality'
	# query_weights_in = '1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1'
	# k_in             = '4'
	num_parties      = 3
	num_workers      = 3
	# partition_scheme = 'vertical'
	# security_level   = 'secure'
	role_number      = 7
	address_list 	 = 'localhost, localhost, localhost, localhost, localhost, localhost'

# Initialize party inputs
num_participants    = num_parties + num_workers
role_numbers        = list(range(num_participants))

# Setup comm environment inputs
allAddresses    = []
roles           = []
address_roots   = []

for address in address_list.split(','):
	address_roots.append(address)
print('address_roots' + str(address_roots))
party_root      = 2000
worker_root     = 3000
manager_root    = 4000

for part in role_numbers:
	if part < num_parties:
		add_tmp = (address_roots[part], party_root + part)
		if part == 1:
			role_tmp = 'query_originator'
		else:
			role_tmp = 'party'
	else:
		add_tmp = (address_roots[part], worker_root + (part - num_parties))
		if part == num_parties:
			role_tmp = 'moderator'
		else:
			role_tmp = 'worker'
	allAddresses.append(add_tmp)
	roles.append(role_tmp)

# Add manager
add_tmp = ('0.0.0.0', manager_root + (part - num_participants))
role_tmp = 'manager'
allAddresses.append(add_tmp)
roles.append(role_tmp)

def TopK_manage(address, num_parties, num_workers, role):
	manager = get_ServerManager(address, num_parties, num_workers, role)
	# queue_list = []
	# for _ in range(num_participants):
	# 	queue = Queue()
	# 	manager.register(f'get_q{_}', callable=lambda:queue_list[_])
	# 	queue_list.append(queue)
	server  = manager.get_server()
	print('\n\n\n\n\n\nManager online: Serving forever')
	server.serve_forever()

# Start manager process...
if __name__ == '__main__':
	process = Process(target=TopK_manage, args=(allAddresses[-1], num_parties, num_workers, roles[-1], ))
	process.start()
