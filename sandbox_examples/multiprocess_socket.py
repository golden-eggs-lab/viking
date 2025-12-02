from time import sleep
from random import random
from multiprocessing import Process
from multiprocessing import Barrier
from threading import BrokenBarrierError
import socket

# target function to prepare some work
def moderator(barrier, number, addresses):
    # Server
    # Create listening socket
    print('moderator_send_port, proc: ' + str(number))
    sp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sp.bind(('localhost', addresses[number]))
    sp.listen(5)

    # wait on all other processes to complete
    try:
        barrier.wait()
        print('done waiting ' + str(number))
    except BrokenBarrierError:
        pass
 
    # Link to other listening socket
    print('moderator_recv_port, proc: ' + str(number))
    rp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    rp.connect(('localhost', addresses[number-1]))

    # Send message loop
    while True:
        # now our endpoint knows about the OTHER endpoint.
        clientsocket, address = sp.accept()
        print(f"Connection from {address} has been established.")
        clientsocket.send(bytes("Hey there!!!","utf-8"))
        clientsocket.send(bytes("quit","utf-8"))
        # clientsocket.send(bytes("Hey there!!!","utf-8"))

        # Receive message loop
        full_msg = ''
        while True:
            msg = rp.recv(8)
            print('Moderator_Start: ' + str(len(msg)) + ', proc: ' + str(number))
            if len(msg) <= 0:
                print('Moderator_Msg_Break')
                break
            full_msg += msg.decode("utf-8")
            msg = ''
            print('Moderator_End: ' + str(len(msg)) + ', proc: ' + str(number))
        # print(full_msg)
        print(full_msg)

# entry point
if __name__ == '__main__':
    # create a barrier
    barrier = Barrier(2 + 1)
    addresses = [1234, 1235]
    # create the worker processes
    for i in range(2):
        # start a new process to perform some work
        worker = Process(target=moderator, args=(barrier, i, addresses))
        worker.start()
    # wait for all processes to finish
    print('Main process waiting on all results...')
    try:
        barrier.wait(timeout=5)
        print('All processes have their result')
    except BrokenBarrierError:
        print('Some processes did not finish on time...')





# import multiprocessing as mp
# import logging
# import socket
# import time

# def moderator(barrier):
#     # Server
#     # Create listening socket
#     print('moderator_send_port')
#     sp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     sp.bind(('localhost', 1234))
#     sp.listen(5)

#     # After listening, wait for other processes to setup listening
#     barrier.wait()

#     # time.sleep(0.5)
#     # Link to other listening socket
#     print('moderator_recv_port')
#     rp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     rp.connect(('localhost', 1235))
#     # sp.setblocking(1)

#     # Send message loop
#     while True:
#         # now our endpoint knows about the OTHER endpoint.
#         clientsocket, address = sp.accept()
#         print(f"Connection from {address} has been established.")
#         clientsocket.send(bytes("Hey there!!!","utf-8"))
#         clientsocket.send(bytes("quit","utf-8"))
#         # clientsocket.send(bytes("Hey there!!!","utf-8"))

#         # Receive message loop
#         full_msg = ''
#         while True:
#             msg = rp.recv(8)
#             print('Moderator_Start: ' + str(len(msg)))
#             if len(msg) <= 0:
#                 print('Moderator_Msg_Break')
#                 break
#             full_msg += msg.decode("utf-8")
#             msg = ''
#             print('Moderator_End: ' + str(len(msg)))
#         # print(full_msg)
#         print(full_msg)


# def party(barrier):
#     # Client
#     # Create listening socket
#     print('party_send_port')
#     sp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     sp.bind(('localhost', 1235))
#     sp.listen(5)

#     # After listening, wait for other processes to setup listening
#     barrier.wait()

#     # Link to other listening socket
#     print('party_recv_port')
#     rp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     rp.connect(('localhost', 1234))

#     # Receive message loop
#     full_msg = ''
#     while True:
#         msg = rp.recv(8)
#         msg_tmp = msg.decode("utf-8")
#         full_msg += msg_tmp
#         if 'quit' in msg_tmp:
#             break
#     print(full_msg)

#     # Send message loop
#     while True:
#         # now our endpoint knows about the OTHER endpoint.
#         clientsocket, address = sp.accept()
#         print(f"Connection from {address} has been established.")
#         clientsocket.send(bytes("Hey there!!!","utf-8"))
#         break





# if __name__ == '__main__':

#     barrier = mp.Barrier(2, timeout=1)
#     process01 = mp.Process(target = moderator(barrier))#, args=(barrier,))
#     process02 = mp.Process(target = moderator(barrier))#, args=(barrier,))
#     process01.start()
#     process02.start()


