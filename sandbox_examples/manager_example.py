from multiprocessing.managers import SyncManager
from multiprocessing import Process, Barrier
import time

class BarClass():
	def __init__(self):
		self.barrier = Barrier(2)

	def get_barrier(self):
		return self.barrier

class ServerManager(SyncManager):
	def __init__(self, bFlag, address, authkey):
		super().__init__(address, authkey)
		if bFlag:
			# print('Barrier set')
			self.initFlag = False
			# self.barrier = self.Barrier(2)
		else:
			self.initFlag = False

	def get_bar(self):
		if not self.initFlag:
			print('get_bar started')
			self.barrier = self.Barrier(2)
			self.initFlag = True
			print('get_bar finished')
		return self.barrier

# Server
barrier = Barrier(2)
barrier1 = Barrier(2)

def start_server():
	# ServerManager.register('Bclass', BarClass)
	# barrier = Barrier(2)
	# barrier1 = Barrier(2)
	ServerManager.register('wait', callable=lambda:barrier)
	ServerManager.register('wait1', callable=lambda:barrier1)
	# ServerManager.register('get_bar', callable=lambda:get_bar)
	m = ServerManager(True, address=('localhost', 4000), authkey=b'abracadabra')
	# m.start()
	s = m.get_server()
	print('Serving forever')
	s.serve_forever()
	
def start_client(role_number):
	# ServerManager.register('Bclass', BarClass)
	ServerManager.register('wait')
	ServerManager.register('wait1')
	m = ServerManager(False, address=('localhost', 4000), authkey=b'abracadabra')
	m.connect()
	# b = m.get_bar()
	# Barrier0
	print('Waitng at barrier0 proc: ' + str(role_number))
	m.wait()
	print('Barrier0 broken')

	# Barrier1
	print('Waitng at barrier1 proc: ' + str(role_number))
	m.wait1()
	print('Barrier1 broken')

# Entry point to processing
if __name__ == '__main__':
    # Initialize processes
    server_proc = Process(target=start_server)
    client_proc = Process(target=start_client, args=(1,))
    time.sleep(1)
    client_proc2 = Process(target=start_client, args=(2,))

    # Start processes
    server_proc.start()
    time.sleep(1)
    client_proc.start()
    time.sleep(1)
    client_proc2.start()

# Enter execution loop
# start_server()
# start_client()








# m = SyncManager(address=('localhost', 2001))
# m.connect()


# from multiprocessing.managers import BaseManager
# m = BaseManager(address=('127.0.0.1', 50000), authkey=b'abc')
# m.connect()


# manager = MyManager(address=('localhost', 3000), authkey=b'')
# manager.get_server().serve_forever()


# from multiprocessing.managers import BaseManager
# from queue import Queue
# queue = Queue()
# class QueueManager(BaseManager): pass
# QueueManager.register('get_queue', callable=lambda:queue)

# from multiprocessing.managers import BaseManager
# class QueueManager(BaseManager): pass
# QueueManager.register('get_queue')
# m = QueueManager(address=('foo.bar.org', 50000), authkey=b'abracadabra')
# m.connect()
# queue = m.get_queue()
# queue.put('hello')



# Client
# from multiprocessing.managers import BaseManager
# class QueueManager(BaseManager): pass
# QueueManager.register('get_queue')
# m = QueueManager(address=('localhost', 4000), authkey=b'abracadabra')
# m.connect()
# queue = m.get_queue()
# queue.put('hello')


# s = m.get_server()
# print('serving')
# s.serve_forever()
# print('done serving')















