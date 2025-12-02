from time import sleep
from random import random
from multiprocessing import Process
from multiprocessing import Barrier
from threading import BrokenBarrierError
import socket
import pickle

def socket_init(self, barrier):
    # Create listening socket
    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.socket.bind(self.address)
    self.socket.listen(5)
    print('Socket setup for proc: ' + str(self.number))

    # wait on all other processes to complete
    try:
        barrier.wait()
        print('Done waiting, proc: ' + str(self.number))
    except BrokenBarrierError:
        pass

    # If party (not moderator), set to receive
    if self.role == 'party':
        while True:
            try:
                connection, client_address = self.socket.accept()
                print('connection from', client_address)
                final_msg = ''

                # Receive loop
                while True:
                    try:
                        data = connection.recv(2048)
                        print('received {!r}'.format(data))
                        # print(data.decode("utf-8"))
                        try:
                            msg = data[:2].decode('utf-8')
                        except:
                            pass
                        if msg != final_msg:
                            final_msg = final_msg + msg
                        print(msg)
                        if msg == 'QW':
                            msg_data          = pickle.loads(data[2:])
                            self.queryWeights = msg_data[0]
                            self.k            = msg_data[1]
                            print('Internal, Query weights set to: ' + str(self.queryWeights) + 'for proc: ' + str(number))
                            break
                            if data:
                                print('sending data back to the client')
                                connection.sendall(data.decrypt('utf-8'))
                            else:
                                print('no data from', client_address)
                                break
                    except EOFError:
                        # If data is empty (i.e. query weights still sending)
                        print('EOFError')
                        pass
                    else:
                        break

            finally:
                # Clean up the connection
                print("Not closing current connection")
                connection.close()
                break

def socket_rcv(connect_address, number, number_connect):
    # Link to other listening socket
    rp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    rp.connect(connect_address)
    print('Proc ' + str(number) + ' connected to proc ' + str(number_connect))

# Send data
# def send_data(destination_address, msg_code, data, number_connect, number):
def send_data(CommEnvir, source_role_number, destination_role_number, msg_code, data):
    while True:
        try:
            # Connect to specified socket
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            while send_socket.connect_ex(CommEnvir.addresses[destination_role_number]) != 0:
                sleep(0.1)
            print('Proc ' + str(source_role_number) + ' connected to proc ' + str(number_connect))
            # print(f"Connection from {address} has been established.")
            data_out = pickle.dumps(data)
            send_socket.send(bytes(msg_code,'utf-8'))
            send_socket.send(data_out)
            break

        finally:
            pass 

# Receive fxn
def rcv_data(self, expected_connections):
    # If moderator, recv from moderator
    connection_count = 0
    while True:
        try:
            connection, client_address = self.socket.accept()
            connection_count += 1
            print('connection from', client_address)
            final_msg = ''

            while True:
                try:
                    data = connection.recv(4096)
                    print('received {!r}'.format(data))
                    # print(data.decode("utf-8"))
                    try:
                        msg = data[:2].decode('utf-8')
                    except:
                        pass
                    if msg != final_msg:
                        final_msg = final_msg + msg
                    print(msg)
                    if msg == 'QW':
                        msg_data          = pickle.loads(data[2:])
                        self.queryWeights = msg_data[0]
                        self.k            = msg_data[1]
                        print('Internal, Query weights set to: ' + str(self.queryWeights) + 'for proc: ' + str(number))
                        break
                        if data:
                            print('sending data back to the client')
                            connection.sendall(data.decrypt('utf-8'))
                        else:
                            print('no data from', client_address)
                            break
                    elif msg == 'KV':
                        msg_data            = pickle.loads(data[2:])
                        self.aggregateTopK.append(msg_data)
                        print('Top-k values received')
                        break
                        # if data:
                        #     print('sending data back to the client')
                        #     connection.sendall(data.decrypt('utf-8'))
                        # else:
                        #     print('no data from', client_address)
                        #     break
                except Exception as e: 
                    print(e)
                else:
                    break
        except Exception as e:
            print(e)

        else:
            # Clean up the connection
            print('Not closing connection')
            print('connection count ' + str(connection_count))
            if connection_count + 1 == expected_connections:
                print("Closing current connection")
                connection.close()
                break


