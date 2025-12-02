from multiprocessing.managers import SyncManager, DictProxy
from multiprocessing import Process, Barrier, Event, Lock, Queue
import multiprocessing as mp
import time
import sys

# REMOTE implementation only

# Top-level queue wrapper so it's picklable and usable by the manager's proxy
class _QueueWrapper:
	def __init__(self, q):
		self._q = q
	def put(self, item, block=True, timeout=None):
		return self._q.put(item, block, timeout)
	def get(self, block=True, timeout=None):
		return self._q.get(block, timeout)
	def empty(self):
		return self._q.empty()
	def qsize(self):
		# qsize may not be reliable on all platforms but is provided
		try:
			return self._q.qsize()
		except Exception:
			return -1

class ServerManager(SyncManager):
	def __init__(self, address, authkey=None):
		super().__init__(address, authkey)


def get_ServerManager(address, num_parties, num_workers, role):
	if role == 'manager':
		# If manager create barriers and event
		num_participants = num_parties + num_workers
		print('num_participants: ' + str(num_participants))
		print('Manager initializing barrier0 with ' + str(num_participants) + ' participants')
		print('Manager initializing barrier1 with ' + str(num_participants - (num_workers - 1)) + ' parties + moderator')
		print('Manager initializing barrier2 with ' + str(num_parties) + ' parties')
		barrier0    = Barrier(num_participants) # All participants + main thread....
		barrier1    = Barrier(num_participants - (num_workers - 1)) # All parties and one mixnet worker (moderator)
		barrier2    = Barrier(num_parties)
		event       = Event()
		lock 		= Lock()
		
		# Pre-create callable functions to avoid lambda overhead
		def get_barrier0(): return barrier0
		def get_barrier1(): return barrier1
		def get_barrier2(): return barrier2
		def get_lock_obj(): return lock
		def get_event_obj(): return event
		
		ServerManager.register('wait0', callable=get_barrier0)
		ServerManager.register('wait1', callable=get_barrier1)
		ServerManager.register('wait2', callable=get_barrier2)
		ServerManager.register('get_lock', callable=get_lock_obj)
		ServerManager.register('set', callable=get_event_obj)

		# Create raw multiprocessing queues local to the manager process
		queue_list = [Queue() for _ in range(num_participants)]
		
		# Pre-create queue wrapper instances to avoid repeated creation
		queue_wrappers = [_QueueWrapper(q) for q in queue_list]
		
		# Pre-create callable functions for each queue to avoid lambda overhead
		def create_queue_getter(index):
			wrapper = queue_wrappers[index]
			def get_queue():
				return wrapper
			return get_queue

		# Register per-queue factory callables with pre-created functions
		for i in range(num_participants):
			ServerManager.register(f'get_q{i}', callable=create_queue_getter(i))

		# Pre-create queues dictionary to avoid repeated dict creation
		queues_dict = {str(i): i for i in range(num_participants)}
		def get_queues_dict():
			return queues_dict
		ServerManager.register('get_queues', callable=get_queues_dict, proxytype=DictProxy)
		# s0 = 0
		# ServerManager.register(f'get_q{s0}', callable=lambda:queue_list[s0])
		# s1 = 1
		# ServerManager.register(f'get_q{s1}', callable=lambda:queue_list[s1])
		# s2 = 2
		# ServerManager.register(f'get_q{s2}', callable=lambda:queue_list[s2])
		# s3 = 3
		# ServerManager.register(f'get_q{s3}', callable=lambda:queue_list[s3])
		# s4 = 4
		# ServerManager.register(f'get_q{s4}', callable=lambda:queue_list[s4])

		# # Check for all after that...
		# if num_participants > 5:
		# 	s5 = 5
		# 	ServerManager.register(f'get_q{s5}', callable=lambda:queue_list[s5])
		# # Check for all after that...
		# if num_participants > 6:
		# 	s6 = 6
		# 	ServerManager.register(f'get_q{s6}', callable=lambda:queue_list[s6])
		# # Check for all after that...
		# if num_participants > 7:
		# 	s7 = 7
		# 	ServerManager.register(f'get_q{s7}', callable=lambda:queue_list[s7])
		# # Check for all after that...
		# if num_participants > 8:
		# 	s8 = 8
		# 	ServerManager.register(f'get_q{s8}', callable=lambda:queue_list[s8])
		# # Check for all after that...
		# if num_participants > 9:
		# 	s9 = 9
		# 	ServerManager.register(f'get_q{s9}', callable=lambda:queue_list[s9])
		# # Check for all after that...
		# if num_participants > 10:
		# 	s10 = 10
		# 	ServerManager.register(f'get_q{s10}', callable=lambda:queue_list[s10])
		# # Check for all after that...
		# if num_participants > 11:
		# 	s11 = 11
		# 	ServerManager.register(f'get_q{s11}', callable=lambda:queue_list[s11])
		# # Check for all after that...
		# if num_participants > 12:
		# 	s12 = 12
		# 	ServerManager.register(f'get_q{s12}', callable=lambda:queue_list[s12])
		# # Check for all after that...
		# if num_participants > 13:
		# 	s13 = 13
		# 	ServerManager.register(f'get_q{s13}', callable=lambda:queue_list[s13])
		# # Check for all after that...
		# if num_participants > 14:
		# 	s14 = 14
		# 	ServerManager.register(f'get_q{s14}', callable=lambda:queue_list[s14])
		# # Check for all after that...
		# if num_participants > 15:
		# 	s15 = 15
		# 	ServerManager.register(f'get_q{s15}', callable=lambda:queue_list[s15])
		# # Check for all after that...
		# if num_participants > 16:
		# 	s16 = 16
		# 	ServerManager.register(f'get_q{s16}', callable=lambda:queue_list[s16])
		# # Check for all after that...
		# if num_participants > 17:
		# 	s17 = 17
		# 	ServerManager.register(f'get_q{s17}', callable=lambda:queue_list[s17])
		# # Check for all after that...
		# if num_participants > 18:
		# 	s18 = 18
		# 	ServerManager.register(f'get_q{s18}', callable=lambda:queue_list[s18])
		# # Check for all after that...
		# if num_participants > 19:
		# 	s19 = 19
		# 	ServerManager.register(f'get_q{s19}', callable=lambda:queue_list[s19])
		# # Check for all after that...
		# if num_participants > 20:
		# 	s20 = 20
		# 	ServerManager.register(f'get_q{s20}', callable=lambda:queue_list[s20])
	else:
		num_participants = num_parties + num_workers
		# ServerManager.register('wait')
		ServerManager.register('wait0')
		ServerManager.register('wait1')
		ServerManager.register('wait2')
		ServerManager.register('get_lock')
		ServerManager.register('set')

		ServerManager.register('get_queues')

		for i in range(num_participants):
			ServerManager.register(f'get_q{i}')

		# ServerManager.register('new_queue')
		# ServerManager.register('get_queues')

		# ServerManager.register('get_q0')
		# ServerManager.register('get_q1')
		# ServerManager.register('get_q2')
		# ServerManager.register('get_q3')
		# ServerManager.register('get_q4')
		# ServerManager.register('get_q5')
	
	# Create server manager instance and return
	server_manager = ServerManager(address, authkey=b'abracadabra')

	# if role == 'manager':
	# 	queue_list = []
		# server_manager.register('get_q', lambda: queue_list)
		# for i in range(num_participants):
		# 	queue_list.append(Queue())
		# 	server_manager.register(f'get_q{i}', callable=lambda:queue_list[i])
			# att_tmp = f'q{i}'
			# server_manager.setattr(att_tmp, i)



	# if role == 'manager':
	# 	queue_list = []
	# 	for _ in range(num_participants):
	# 		queue = Queue()
	# 		server_manager.register(f'get_q{_}', callable=lambda:queue_list[_])
	# 		queue_list.append(queue)

	return server_manager


if __name__ == '__main__':
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
		else:
			add_tmp = (address_root, worker_root + (part - num_parties))
			if part == num_parties:
				role_tmp = 'moderator'
			else:
				role_tmp = 'worker'
		allAddresses.append(add_tmp)
		roles.append(role_tmp)

	# Add manager
	add_tmp = (address_root, manager_root + (part - num_participants))
	role_tmp = 'manager'
	allAddresses.append(add_tmp)
	roles.append(role_tmp)
	
	def TopK_manage(address, num_parties, num_workers, role):
		manager = get_ServerManager(address, num_parties, num_workers, role)
		server  = manager.get_server()
		print('\n\n\n\n\n\nManager online: Serving forever')
		server.serve_forever()

	# Start manager process...
	process = Process(target=TopK_manage, args=(allAddresses[-1], num_parties, num_workers, roles[-1], ))
	process.start()


# Server
# def start_server():
# 	barrier0 = Barrier(2)
# 	barrier1 = Barrier(2)
# 	ServerManager.register('wait0', callable=lambda:barrier0)
# 	ServerManager.register('wait1', callable=lambda:barrier1)
# 	m = ServerManager(True, address=('localhost', 4000), authkey=b'abracadabra')
# 	s = m.get_server()
# 	print('Serving forever')
# 	s.serve_forever()
	
# def start_client():
# 	ServerManager.register('wait0')
# 	ServerManager.register('wait1')
# 	m = ServerManager(False, address=('localhost', 4000), authkey=b'abracadabra')
# 	m.connect()

	# # Barrier0
	# print('Waitng at barrier0')
	# m.wait0()
	# print('Barrier0 broken')

	# # Barrier1
	# print('Waitng at barrier1')
	# m.wait1()
	# print('Barrier1 broken')


# # Entry point to processing
# if __name__ == '__main__':
#     # Initialize processes
#     server_proc = Process(target=start_server)
#     client_proc = Process(target=start_client)
#     client_proc2 = Process(target=start_client)

#     # Start processes
#     server_proc.start()
#     time.sleep(1)
#     client_proc.start()
#     client_proc2.start()

