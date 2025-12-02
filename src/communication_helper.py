import heapq
import time
import os
from threading import BrokenBarrierError, Lock
from multiprocessing.connection import Listener, Client, wait
import numpy as np
import pickle
import logging
# import seal
# import sealp
from concurrent.futures import ThreadPoolExecutor
from messages import EntryStorage
import threading
import queue

picklingFlag = False
log = logging.getLogger('fedtopk')

class CommunicationEnvironment():
    def __init__(self, addresses, numberParties, numberWorkers, roles):#, lock):
        self.addresses          = addresses
        self.numberParties      = numberParties # Parties will be the first P addresses in list
        self.numberWorkers      = numberWorkers # Workers will be three
        self.numberParticipants = self.numberParties + self.numberWorkers
        self.roles              = roles
        self.messageKeys        = ['QW', 'KV', 'KM', 'EK', 'PK', 'GP', 'GK', 'MM', 'VM', 'RE', 'DR', 'IC', 'XX', 'QR', 'RG', 'RS', 'CM', 'CQ']
        # [Query Weights, K-Values, ElGamal Public Key, Paillier Private Key, Galois Keys, Horizontally Mixnet, Vertically Mixnet, Refresh Round, Decryption Round, ID Compare]
        
        self.message_thread_pool = ThreadPoolExecutor(max_workers=8)

        self.message_locks = {
            'msg_store': Lock(),
            'aggregateTopK': Lock(),
            'ElGamalPubKeys': Lock(),
            'PaillierPubKeys': Lock(),
            'ID_store': Lock(),
            'ID_set': Lock(),
            'pir_queries': Lock(),
            'topKreturn': Lock(),
            'checkTA': Lock(),
            'RcvStatus': Lock(),
        }

        # Track outstanding async heap insertions; used to decide when to end a round
        self.pending_heap_inserts = 0
        
        # Async send configuration
        self.send_thread_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="SendWorker")
        self.send_callbacks = {}  # Store callbacks for critical messages
        self.send_acks = {}  # Store acknowledgment tracking
        self.send_locks = {
            'callbacks': Lock(),
            'acks': Lock(),
        }
        
        # Message types that require acknowledgment
        self.critical_message_types = {'QW', 'EK', 'PK', 'GP', 'TA', 'SG', 'QR'}

    def SetupSocket(self):
        # Create listening socket
        # 0.0.0.0 listen on all channels
        # print(f'communication_helper: listener_input2 = {self.addresses[self.roleNumber][1]}')
        self.socket = Listener(('0.0.0.0', self.addresses[self.roleNumber][1]))

        try:
            # log.debug('Waiting at socket setup barrier, proc: ' + str(self.roleNumber))
            b = self.manager.wait0().wait()#barrier.wait()
            # log.debug('Socket setup barrier broken, proc: ' + str(self.roleNumber) + ', return value = ' + str(b))
            elapsed_time = round(time.time() - self.startTime, 5)
            log.debug(f'Elapsed time CONNECT: {elapsed_time}')
            # time.sleep(1)
        except Exception as e:
            log.debug('Setup socket barrier error...')
            # time.sleep(1)

    def SendDirect(self, source_role_number, destination_role_number, msg_code, data, num_senders):
        rcv_cnt = 0
        send_start = time.time()
        # while True:
            # acq = self.manager.get_lock().acquire(block=False)
            # print('Rcv_cnt at proc: ' + str(self.roleNumber) + ' = ' + str(rcv_cnt))
            # if acq:
                # while True:
                    # try:
        send_addr = self.addresses[destination_role_number]
        # print(f'Sending to: {send_addr}')
        # conn = Client(send_addr)
        # conn.send([msg_code, data, time.time()])

        get_queue_fxn_tmp = getattr(self.manager, 'get_q' + str(destination_role_number))
        get_queue_fxn_tmp().put([source_role_number, msg_code, data, time.time()])

        log.debug('Msg code: ' + str(msg_code) + ' at proc: ' + str(self.roleNumber))
        msg_pickle  = pickle.dumps([msg_code, data], -1)
        msg_size    = len(msg_pickle)
        # log.debug('Message size = ' + str(msg_size) + ' bytes')
        self.CommunicationMB += msg_size
        # print(f'Running communication size = {self.CommunicationMB} at proc {self.roleNumber}')

                #         break
                #     except ConnectionRefusedError as e:
                #         log.debug('Connection error at proc: ' + str(self.roleNumber))
                #         log.debug(e)
                #         sleep(0.01)
                #     finally:
                #         pass
                # self.manager.get_lock().release()
                # break
            # elif rcv_cnt < (num_senders - 1):
            #     try:
            #         if self.partitionScheme == 'horizontal':
            #             expected_connections = 1
            #             log.debug('Rcv at proc: ' + str(self.roleNumber))
            #             self.RcvData(expected_connections, 0)
            #             rcv_cnt += 1
            #         elif self.partitionScheme == 'vertical':
            #             expected_connections = 1
            #             self.RcvData(expected_connections, 0)
            #             # self.connection_count += 1
            #             rcv_cnt += 1
            #     except Exception as e:
            #         log.debug(e)
            # else:
            #     sleep(0.01)

        send_end = time.time()
        send_time = send_end - send_start
        # log.debug(f"communication_helper: {send_time}")

    def SendData(self, source_role_number, destination_role_number, msg_code, data, through_mix, num_senders, callback=None, wait_for_ack=False):
        """
        Asynchronous SendData method with fire-and-forget and callback support
        
        Args:
            source_role_number: Source role number
            destination_role_number: Destination role number  
            msg_code: Message code
            data: Message data
            through_mix: Whether to send through mixnet
            num_senders: Number of senders (legacy parameter)
            callback: Optional callback function to call after successful send
            wait_for_ack: Whether to wait for acknowledgment (default: False for fire-and-forget)
        """
        # Submit send operation to thread pool for async execution
        future = self.send_thread_pool.submit(
            self._async_send_worker,
            source_role_number, destination_role_number, msg_code, data, 
            through_mix, num_senders, callback, wait_for_ack
        )
        
        # If callback provided, store it for later execution
        if callback:
            with self.send_locks['callbacks']:
                self.send_callbacks[id(future)] = callback
                
        return future

    def _async_send_worker(self, source_role_number, destination_role_number, msg_code, data, through_mix, num_senders, callback=None, wait_for_ack=False):
        """
        Worker function that performs the actual send operation asynchronously
        """
        try:
            # Perform the actual send operation
            if through_mix:
                # Message from party to first worker
                if source_role_number < self.numberParties:
                    self.SendDirect(source_role_number, self.numberParties, msg_code, data, num_senders)
                # Last worker send to destination
                elif source_role_number == (self.numberParticipants - 1):
                    self.SendDirect(self.roleNumber, destination_role_number, msg_code, data, num_senders)
                # All workers in the middle, send to the next worker
                else:
                    self.SendDirect(self.roleNumber, self.roleNumber + 1, msg_code, data, num_senders)
            else:
                self.SendDirect(source_role_number, destination_role_number, msg_code, data, num_senders)
            
            # Execute callback if provided
            if callback:
                try:
                    callback(True, msg_code, destination_role_number)  # success=True
                except Exception as e:
                    log.debug(f"Callback execution failed: {e}")
            
            # Handle acknowledgment if required
            if wait_for_ack and msg_code in self.critical_message_types:
                self._wait_for_acknowledgment(msg_code, destination_role_number)
                
        except Exception as e:
            log.debug(f"Async send failed for {msg_code} to {destination_role_number}: {e}")
            if callback:
                try:
                    callback(False, msg_code, destination_role_number)  # success=False
                except Exception as e:
                    log.debug(f"Error callback execution failed: {e}")

    def _wait_for_acknowledgment(self, msg_code, destination_role_number, timeout=5):
        """
        Wait for acknowledgment from destination (if required)
        """
        ack_key = f"{msg_code}_{destination_role_number}"
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            with self.send_locks['acks']:
                if ack_key in self.send_acks and self.send_acks[ack_key]:
                    del self.send_acks[ack_key]
                    return True
            time.sleep(0.01)
        
        log.debug(f"Acknowledgment timeout for {msg_code} to {destination_role_number}")
        return False

    def register_acknowledgment(self, msg_code, source_role_number):
        """
        Register acknowledgment from source (called by receiver)
        """
        ack_key = f"{msg_code}_{source_role_number}"
        with self.send_locks['acks']:
            self.send_acks[ack_key] = True

    def SendDataSync(self, source_role_number, destination_role_number, msg_code, data, through_mix, num_senders):
        """
        Synchronous version of SendData for backward compatibility
        """
        future = self.SendData(source_role_number, destination_role_number, msg_code, data, through_mix, num_senders)
        return future.result()  # Block until completion

    def _process_next_pending_sx(self):
        """
        For secure mode: when the ID barrier is lowered, immediately process the
        next pending entry from `msg_store` by running ComparativeMixnetID on a
        single entry and forwarding it as an 'ID' message. This prevents stalling
        when we previously continued on 'SX' due to the barrier being set.
        """
        try:
            if self.security_level == 'secure':
                if not self.checkID_barrier:
                    self.checkID_barrier = True
                    single_entry = [self.msg_store[0]]
                    assert single_entry[0].encValueInvert is not None
                    mix_msg_data = self.ComparativeMixnetID(single_entry)
                    num_senders = 1
                    self.SendData(self.roleNumber, self.roleNumber + 1, 'ID', mix_msg_data, True, num_senders)
                    self.msg_store.pop(0)
                # Do not end the round here just because msg_store is empty.
                # The round completion is signaled elsewhere (e.g., on 'QR').
        except Exception as e:
            print(f"Error in _process_next_pending_sx: {e}")

    def on_heap_push_complete(self):
        """
        Callback from heap after an async push completes. Release ID barrier and
        trigger processing of the next pending SX item (if any).
        """
        try:
            if self.security_level == 'secure':
                # Always release the barrier
                self.checkID_barrier = False
                # If there are pending SX items, immediately process the next one
                if len(self.msg_store) > 0:
                    self._process_next_pending_sx()
                else:
                    # If no pending SX, decide whether to initiate TK
                    smallest_entry = self.ID_store.peek() if hasattr(self, 'ID_store') else None
                    if smallest_entry is not None and self.TA is not None:
                        threshold_entry = EntryStorage()
                        threshold_entry.encValue = self.TA
                        mix_msg_data = self.ComparativeMixnetScore([smallest_entry, threshold_entry])
                        num_senders = 1
                        self.SendData(self.roleNumber, self.roleNumber + 1, 'TK', mix_msg_data, True, num_senders)
                        elapsed_time = round(time.time() - self.startTime, 5)
                        log.debug(f'Elapsed time TK: {elapsed_time}')
        except Exception as e:
            print(f"Error in on_heap_push_complete: {e}")

    # Receive fxn
    def RcvData(self, expected_connections=None, current_connections=None):
        if expected_connections is None:
            expected_connections = self.exp_connects

        if current_connections is None:
            current_connections = self.connection_count

        timeout_counter = 0
        while current_connections < expected_connections:
            timeout_counter += 1
            # for connection in wait([self.socket.accept()], timeout=1):
            if 1:
                # try:
                # rcv_data = connection.recv()

                get_queue_fxn_tmp = getattr(self.manager, 'get_q' + str(self.roleNumber))
                rcv_data = get_queue_fxn_tmp().get()
                # print(f"rcv_data = {rcv_data}")
                current_connections     += 1
                msg_flag                = 0
                try:
                    try:
                        msg_from    = rcv_data[0]
                        msg         = rcv_data[1]
                        msg_data    = rcv_data[2]
                        msg_time    = rcv_data[3]
                        # log.debug('Message time = ' + str(time.time() - msg_time))
                        print(f"Msg rcv'd = {msg} at proc: {self.roleNumber}")
                    except:
                        pass

                    if msg == 'QW':
                        self.queryWeights   = msg_data[0]
                        self.k              = msg_data[1]
                        # Register acknowledgment for critical message
                        self.register_acknowledgment(msg, msg_from)
                        # log.debug('k = ' + str(self.k))

                    elif msg == 'KV':
                        # If first or second worker, send to next worker in chain...
                        if self.roleNumber >= self.numberParties and self.roleNumber < (self.numberParticipants - 1):
                            mix_msg_data = self.RefreshMixnet(msg_data)
                            
                            # Unpack and append messsage
                            for msg_tmp in mix_msg_data:
                                self.msg_store.append(msg_tmp)

                            if len(self.msg_store) >= self.batchSize:
                                num_senders = 1
                                # log.debug('Sending KV to ' + str(self.roleNumber + 1))
                                self.SendData(self.roleNumber, self.roleNumber + 1, 'KV', self.msg_store, True, num_senders)

                        # If last worker, send to moderator...
                        elif self.roleNumber == (self.numberParticipants - 1):
                            mix_msg_data            = self.RefreshMixnet(msg_data)
                            num_senders = 1
                            destination_role_number = self.roles.index('moderator')
                            # log.debug('KM to: ' + str(destination_role_number))
                            self.SendData(self.roleNumber, destination_role_number, 'KM', mix_msg_data, True, num_senders)
                        else:
                            self.aggregateTopK.append(msg_data)
                    elif msg == 'KM':
                        self.aggregateTopK.append(msg_data)
                    elif msg == 'EK':
                        self.ElGamalPubKeys.append(msg_data)
                        # Register acknowledgment for critical message
                        self.register_acknowledgment(msg, msg_from)
                    elif msg == 'PK':
                        self.PaillierPubKeys.append(msg_data)
                        # Register acknowledgment for critical message
                        self.register_acknowledgment(msg, msg_from)
                    elif msg == 'GP':
                        self.ElGamalInfo     = msg_data
                        # Register acknowledgment for critical message
                        self.register_acknowledgment(msg, msg_from)
                    elif msg == 'MM':
                        # If second worker, send to next worker in chain...
                        if self.roleNumber <= (self.numberParticipants - 2) and (self.roleNumber != self.numberParties):
                            mix_msg_data = self.MultiplicativeMixnet(msg_data)
                            num_senders = 1
                            self.SendData(self.roleNumber, self.roleNumber + 1, 'MM', mix_msg_data, True, num_senders)

                        # If last worker, send to moderator...
                        if self.roleNumber == (self.numberParticipants - 1):
                            mix_msg_data    = self.MultiplicativeMixnet(msg_data)
                            encoding_length = len(mix_msg_data[0])
                            gtFlag          = False
                            for i in range(0, encoding_length):
                                if mix_msg_data[0][i][1] == mix_msg_data[1][i][1]:
                                    gtFlag = True
                            destination_role_number = self.roles.index('moderator')
                            num_senders = 1
                            self.SendData(self.roleNumber, destination_role_number, 'MM', gtFlag, True, num_senders)
                        else:
                            self.compare_vals = msg_data
                    elif msg == 'XX':
                        # print('Msg: XX, proc: ' + str(self.roleNumber))
                        self.RcvCheck += 1
                        # print(self.RcvCheck)
                        if self.roleNumber < self.numberParties:
                            # print('Rcv count at proc: ' + str(self.roleNumber) + ' = ' + str(self.RcvCheck))
                            if self.RcvCheck == self.numberParties:
                                self.RcvStatus = False
                        else:
                            if self.RcvCheck == self.numberParties:
                                self.RcvStatus = False
                    elif msg == 'QR':
                        # Register acknowledgment for critical message
                        self.register_acknowledgment(msg, msg_from)
                        if self.partitionScheme == 'horizontal':
                            # If second worker, send to next worker in chain...
                            if self.roleNumber <= (self.numberParticipants - 2) and (self.roleNumber > self.numberParties):
                                mix_msg_data = self.DecryptionMixnet(msg_data)
                                num_senders = 1
                                self.SendData(self.roleNumber, self.roleNumber + 1, 'QR', mix_msg_data, True, num_senders)

                            # If last worker, send to party...
                            elif self.roleNumber == (self.numberParticipants - 1):
                                mix_msg_data = self.DecryptionMixnet(msg_data)
                                query_return = []
                                for ind in range(0, self.k):
                                    query_return.append(mix_msg_data[ind][1])
                                num_senders             = 1
                                for p in range(0, self.numberParties):
                                    destination_role_number = p
                                    self.SendData(self.roleNumber, destination_role_number, 'QR', query_return, True, num_senders)
                            else:
                                self.topKreturn = msg_data
                        elif self.partitionScheme == 'vertical':
                            if self.roleNumber < (self.numberParticipants - 1) and self.roleNumber > self.numberParties:
                                if self.security_level == 'secure':
                                    mix_msg_data = self.DecryptionMixnet(msg_data)
                                elif self.security_level == 'nonsecure':
                                    mix_msg_data = msg_data

                                num_senders = 1
                                self.SendData(self.roleNumber, self.roleNumber + 1, 'QR', mix_msg_data, True, num_senders)

                            # If last worker, send to party...
                            elif self.roleNumber == (self.numberParticipants - 1):
                                if self.security_level == 'secure':
                                    mix_msg_data = self.DecryptionMixnet(msg_data)
                                query_return = []
                                if self.security_level == 'secure':
                                    for ind in range(0, self.k):
                                        query_return.append(mix_msg_data[ind][1])
                                elif self.security_level == 'nonsecure':
                                    query_return = msg_data

                                num_senders = 1
                                for p in range(0, self.numberParties):
                                    destination_role_number = p
                                    # self.SendData(self.roleNumber, destination_role_number, 'QR', query_return, True, num_senders)
                                    # Queue replace
                                    get_queue_fxn_tmp = getattr(self.manager, 'get_q' + str(p))
                                    get_queue_fxn_tmp().put([self.roleNumber, 'QR', query_return])
                                    self.calc_data_size([self.roleNumber, 'QR', query_return])
                            else:
                                print('Received QR at proc: ' + str(self.roleNumber))
                                self.topKreturn  = msg_data
                                self.checkTA     = False
                    elif msg == 'TA':
                        log.debug('Msg rcvd: TA, proc: ' + str(self.roleNumber))
                        # Register acknowledgment for critical message
                        self.register_acknowledgment(msg, msg_from)
                        
                        # Only moderator (first worker) processes TA messages
                        if self.roleNumber == self.numberParties:
                            for msg_tmp in msg_data:
                                self.msg_store.append(msg_tmp)

                            if len(self.msg_store) >= self.batchSize:
                                # Process threshold value without mixnet
                                if self.security_level == 'secure':
                                    # Extract threshold value directly without shuffle
                                    self.TA = self.AdditiveMixnetTA(self.msg_store)[0].encValue
                                    
                                elif self.security_level == 'nonsecure':
                                    # Sum input values for nonsecure mode
                                    sum_val = 0
                                    for msg in self.msg_store:
                                        sum_val += msg.value
                                    self.TA = sum_val
                                    log.debug(f"TA sum: {self.TA} at proc: {self.roleNumber}")

                                # Clear message store
                                self.msg_store = []
                                self.sum_val = [1, 1]
                                self.sum_val_noEnc = 0
                                
                                # Wait at barrier after TA processing
                                try:
                                    log.debug(f'Moderator waiting at barrier1 after TA: proc {self.roleNumber}')
                                    self.manager.wait1().wait()
                                    self.checkID_barrier = False
                                    self.countIDs = 0
                                    log.debug(f'Moderator passed barrier1 after TA: proc {self.roleNumber}')
                                except BrokenBarrierError:
                                    log.debug('barrier1 err in TA processing')
                                    pass
                    elif msg == 'TM':
                        # TM message is deprecated - keeping for backward compatibility
                        log.debug('Msg: TM (deprecated), proc: ' + str(self.roleNumber))
                        pass
                    elif msg == 'IS':
                        # Handle batch IS messages
                        for item in msg_data:
                            if item.newID:
                                # de-dup finishes, insert into ID_store
                                if self.security_level == 'secure':
                                    # Track async insert and push
                                    if len(self.ID_store.sorted_list) == 0:
                                        self.ID_store.insert(item)
                                        self.on_heap_push_complete()
                                        continue
                                    else:
                                        # print(f"item.encValue = {item.encValue}")
                                        mix_msg_data = self.ComparativeMixnetScoreBatch(item)
                                        num_senders  = 1
                                        self.SendData(self.roleNumber, self.roleNumber + 1, 'CM', mix_msg_data, True, num_senders)
                                    # self.pending_heap_inserts += 1
                                    # self.ID_store.push_async(item)
                            else:
                                self.on_heap_push_complete()
                            

                        # if self.security_level == 'secure':
                        #     # Send and receive RS
                        #     self.genDistRandNum()
                        #     self.connection_count, self.exp_connects = 0, 1
                        #     self.RcvData()
                    elif msg == 'CM':
                        # Only process CM if we are NOT the moderator (who initiated the CM)
                        # Moderator should not process its own CM messages
                        # If middle workers, send to next worker
                        if self.roleNumber < (self.numberParticipants - 1):
                            # mix_msg_data = self.ComparativeMixnetScore(msg_data)
                            mix_msg_data = self.ComparativeMixnetScoreBatch(msg_data)
                            num_senders  = 1
                            # print(f"Processing CM at worker {self.roleNumber}, sending to next worker {self.roleNumber + 1}")
                            self.SendData(self.roleNumber, self.roleNumber + 1, 'CM', mix_msg_data, True, num_senders)
                        # If last worker, send CQ back to moderator
                        elif self.roleNumber == (self.numberParticipants - 1):
                            # print(f"Processing CM at last worker {self.roleNumber}, sending CQ to moderator")
                            # mix_msg_data = self.ComparativeMixnetScore(msg_data)
                            mix_msg_data = self.ComparativeMixnetScoreBatch(msg_data)
                            destination_role_number = self.roles.index('moderator')
                            #  At last, mixnet will return a list of bools 
                            num_senders  = 1
                            self.SendData(self.roleNumber, destination_role_number, 'CQ', mix_msg_data, True, num_senders)
                    
                    elif msg == 'CQ':
                        # Handle CQ message - comparison result from mixnet workers
                        try:
                            # Empty payload guard
                            if not msg_data:
                                self.on_heap_push_complete()
                                continue
                            # Busy-wait flags for heap to poll
                            new_entry = EntryStorage()
                            new_entry.ID = msg_data[0].ID
                            new_entry.noEncID = msg_data[0].noEncID
                            new_entry.encValue = msg_data[0].encValue
                            new_entry.encValueInvert = msg_data[0].encValueInvert
                            # print(f"ID = {new_entry.noEncID}")

                            comparison_result = []
                            for i, diff_score in enumerate(msg_data):
                                is_smaller = diff_score.equalityCheck < 0
                                comparison_result.append(is_smaller)
                                # print(f"  Compare[{i}]: new_item < heap[{i}] = {is_smaller} (diff={diff_score.equalityCheck})")


                            self.ID_store.insert_comparison_result(new_entry, comparison_result)
                            self.on_heap_push_complete()
                        except Exception as e:
                            print(f"Error forwarding CQ to heap: {e}")
                    
                    elif msg == 'RG':
                        # log.debug('RG rcvd at proc: ' + str(self.roleNumber))
                        self.Gamma += msg_data
                        if self.roleNumber == (self.numberParticipants - 1):
                            log.debug('Gamma = ' + str(self.Gamma) + ' and u = ' + str(self.PaillierSend.pkey.u) + ' and diff = ' + str(self.PaillierSend.pkey.u - self.Gamma) + ' at proc: ' + str(self.roleNumber))
                    elif msg == 'RS':
                        # print('RS received at proc: ' + str(self.roleNumber))
                        c0, c1                              = msg_data[0], msg_data[1]
                        sum_val_tmp                         = [1, 1]
                        sum_val_tmp[0], sum_val_tmp[1]      = self.sum_val[0] * c0, self.sum_val[1] * c1
                        self.sum_val[0], self.sum_val[1]    = gmpy2.f_mod(sum_val_tmp[0], self.ElGamalInfo.p), gmpy2.f_mod(sum_val_tmp[1], self.ElGamalInfo.p)
                        # print('sum_val at RS = ' + str(self.sum_val) + ' at proc: ' + str(self.roleNumber))

                        # Unencrypted check...
                        self.sum_val_noEnc  += msg_data[2]
                        # log.debug('Unencrypted sum = ' + str(self.sum_val_noEnc) + ' at proc: ' + str(self.roleNumber))
                        # If not moderator generate random number
                        if self.roleNumber != (self.numberParties):
                            self.genDistRandNum()
                    elif msg == 'GK':
                        pass
                        # # print('Msg: GK, proc: ' + str(self.roleNumber))# + ' received. Msg data: ' + str(msg_data))
                        # # msg_data.pubKey = object_to_base64(msg_data.pubKey)
                        # # print('Key received: ' + str(msg_data.pubKey) + ' from proc: ' + str(msg_data.partyOfOrigin))
                        # gk_ind          = msg_data[0]
                        # gk_keys_bytes   = msg_data[1]

                        # # Write bytes to file for read-in to GaloisKeys constructor
                        # newFilePath = 'gk' + str(self.roleNumber) + str(gk_ind) + '.bin'
                        # newFile     = open(newFilePath, "wb")
                        # writeInfo   = bytearray(gk_keys_bytes)
                        # newFile.write(writeInfo)

                        # # Create "new" Galois key instance
                        # gk = seal.GaloisKeys()
                        # gk_context = seal.SEALContext(self.enc_params)
                        # gk.load(gk_context, newFilePath)
                        # # print('Galois keys loaded: ' + str(gk.to_string()))
                        # # Set key for other parties...
                        # self.pir_server.set_galois_key(gk_ind, gk)
                    elif msg == 'PQ':
                        # print('Query: ' + str(msg_data.query) + ' from proc: ' + str(msg_data.partyOfOrigin))
                        self.pir_queries.append(msg_data)
                        # size_per_item    = self.e_bit_len * 2 // 8
                        # ele_index = msg_data[-1]
                        # start_ind   = ele_index * size_per_item
                        # end_ind     = (ele_index + 1) * size_per_item
                        # print('PQ rcvd at proc: ' + str(self.roleNumber) + ' from proc: ' + str(msg_data[0]) + ' for ID: ' + str(msg_data[-1]) + ' ' + str(self.db_enc[start_ind:end_ind]))
                    elif msg == 'PR':
                        # print('PR received at proc: ' + str(self.roleNumber))
                        if self.security_level == 'secure':
                            reply_deserial      = self.pir_client.deserialize_reply(msg_data[1])
                            elems               = self.pir_client.decode_reply(reply_deserial, self.offset)
                            c0, c1              = self.pir_to_encrypted_pair(elems)
                            sum_tmp             = [self.currentIDsum[0] * c0, self.currentIDsum[1] * c1]
                            self.currentIDsum   = sum_tmp
                        elif self.security_level == 'nonsecure':
                            # log.debug('Adding PR value: ' + str(msg_data[1]) + ', at proc: ' + str(self.roleNumber))
                            self.currentIDsum += msg_data[1]
                            # log.debug('Current sum = ' + str(self.currentIDsum) + ', at proc: ' + str(self.roleNumber))
                        # print('PR uint8 rcvd at proc: ' + str(self.roleNumber) + ' from proc: ' + str(msg_data[0]) + ' for ID: ' + str(msg_data[-1]) + '\n' + str(elems))
                        # print('PR rcvd at proc: ' + str(self.roleNumber) + ' from proc: ' + str(msg_data[0]) + ' for ID: ' + str(msg_data[-1]) + ' ' + str([c0, c1]))
                        
                        # self.countSR += 1
                        #log.debug('Current ID sum at proc: ' + str(self.roleNumber) + ' value = ' + str(self.currentIDsum))
                    elif msg == 'SG':
                        # Register acknowledgment for critical message
                        self.register_acknowledgment(msg, msg_from)
                        # First worker aggregates then forwards asynchronously
                        if self.roleNumber == self.numberParties:
                            # Unpack and append message
                            for msg_tmp in msg_data:
                                self.msg_store.append(msg_tmp)
                            if len(self.msg_store) >= self.batchSize:
                                # Copy current batch to avoid mutation races
                                batch_copy = list(self.msg_store)
                                self.msg_store = []
                                self.sum_val = [1, 1]
                                self.sum_val_noEnc = 0

                                def _process_and_forward_sg_first(batch=batch_copy):
                                    if self.security_level == 'secure':
                                        mix_msg_data = self.AdditiveMixnet(batch)
                                    else:
                                        mix_msg_data = batch
                                    num_senders = 1
                                    # Forward to next worker without blocking listener
                                    self.SendData(self.roleNumber, self.roleNumber + 1, 'SG', mix_msg_data, True, num_senders)

                                # Offload compute + send
                                self.send_thread_pool.submit(_process_and_forward_sg_first)
                        # Intermediate worker forwards asynchronously
                        elif self.roleNumber < (self.numberParticipants - 1) and self.roleNumber > self.numberParties:
                            def _forward_sg_mid(msg_data_local=msg_data):
                                if self.security_level == 'secure':
                                    mix_msg_data = self.AdditiveMixnet(msg_data_local)
                                else:
                                    mix_msg_data = msg_data_local
                                num_senders = 1
                                self.SendData(self.roleNumber, self.roleNumber + 1, 'SG', mix_msg_data, True, num_senders)
                            self.sum_val = [1, 1]
                            self.sum_val_noEnc = 0
                            self.send_thread_pool.submit(_forward_sg_mid)
                        # Last worker sends SX to moderator asynchronously
                        elif self.roleNumber == (self.numberParticipants - 1):
                            def _send_sx(msg_data_local=msg_data):
                                if self.security_level == 'secure':
                                    mix_msg_data = self.AdditiveMixnet(msg_data_local)
                                else:
                                    mix_msg_data = msg_data_local
                                num_senders             = 1
                                destination_role_number = self.roles.index('moderator')
                                self.SendData(self.roleNumber, destination_role_number, 'SX', mix_msg_data, False, num_senders)
                                elapsed_time = round(time.time() - self.startTime, 5)
                                log.debug(f'Elapsed time SX: {elapsed_time}')
                            self.sum_val = [1, 1]
                            self.sum_val_noEnc = 0
                            self.send_thread_pool.submit(_send_sx)
                    elif msg == 'SX':
                            
                        for entry_tmp in msg_data:
                            self.msg_store.append(entry_tmp)
                            # print('Msg SX store, proc: ' + str(self.roleNumber))
                    
                        if len(self.msg_store) >= self.batchSize and self.security_level == 'nonsecure':
                            for entry_tmp in self.msg_store:
                                    # newID = True
                                    entry_id = entry_tmp.noEncID
                                    entry_tmp.value = entry_tmp.encValue
                                    if entry_id not in self.ID_set:
                                        self.ID_set.add(entry_id)
                                        if len(self.ID_store) < self.k:
                                            heapq.heappush(self.ID_store, entry_tmp)
                                        else:
                                            if entry_tmp.value > self.ID_store[0].value:
                                                heapq.heapreplace(self.ID_store, entry_tmp)
                            print(f"self.TA = {self.TA}")
                   
                            smallest_entry = self.ID_store[0]
                            print(f"Smallest entry in heap: ID={smallest_entry.noEncID}, value={smallest_entry.value}")
                            if self.TA <= smallest_entry.value and len(self.ID_store) == self.k:
                                self.thresholdCheck = True
                            else:
                                self.thresholdCheck = False
                            self.checkTA = False
                            # mix_msg_data = self.msg_store

                            # num_senders  = 1
                            # print(mix_msg_data)
                            # self.SendData(self.roleNumber, self.roleNumber + 1, 'ID', mix_msg_data, True, num_senders)
                            self.msg_store = []
                        elif self.security_level == 'secure':
                            # If barrier is free, immediately kick off next pending SX entry
                            self._process_next_pending_sx()


                        # Output timing after each round
                        # elapsed_time = round(time.time() - self.startTime, 5)
                        # log.debug('Elapsed time SX: ' + str(elapsed_time))
                    elif msg == 'ID':
                        if self.security_level == 'secure':
                            mix_msg_data = self.ComparativeMixnetID(msg_data)
                        elif self.security_level == 'nonsecure':
                            mix_msg_data = msg_data
                        # If second to last worker, send to next worker
                        if self.roleNumber < (self.numberParticipants - 1) and self.roleNumber > self.numberParties:
                            num_senders  = 1
                            self.SendData(self.roleNumber, self.roleNumber + 1, 'ID', mix_msg_data, True, num_senders)
                        elif self.roleNumber == (self.numberParticipants - 1):
                            num_senders             = 1
                            # send all msg_data to the moderator as a batch
                            destination_role_number = self.roles.index('moderator') 
                            self.SendData(self.roleNumber, destination_role_number, 'IS', mix_msg_data, False, num_senders)
                                
                    elif msg == 'TK':
                        if self.roleNumber < (self.numberParticipants - 1) and self.roleNumber > self.numberParties:
                            mix_msg_data = self.ComparativeMixnetScore(msg_data)
                            num_senders  = 1
                            self.SendData(self.roleNumber, self.roleNumber + 1, 'TK', mix_msg_data, True, num_senders)
                        elif self.roleNumber == (self.numberParticipants - 1):
                            mix_msg_data = self.ComparativeMixnetScore(msg_data)
                            num_senders  = 1
                            destination_role_number = self.roles.index('moderator')
                            self.SendData(self.roleNumber, destination_role_number, 'KX', mix_msg_data, True, num_senders)
                    elif msg == 'KX':
                        if len(self.ID_store.sorted_list) == self.ID_store.k and msg_data[0].encValue <= 0:
                            self.thresholdCheck = True
                        else:
                            self.thresholdCheck = False
                        self.checkTA = False

                    elif msg == 'TR':
                        pass
                        log.debug('Msg TR, algo continues at proc: ' + str(self.roleNumber))

                    elif msg == 'PQ':
                        pass
                        log.debug('Msg PQ, algo continues at proc: ' + str(self.roleNumber))

                    elif msg == 'PR':
                        pass
                        log.debug('Msg PR, algo continues at proc: ' + str(self.roleNumber))

                except EOFError as e: 
                    log.debug('exception01')
                    log.debug(e)
                # else:
                #     print('Else break proc:' + str(self.roleNumber))
                #     break
                # except Exception as e:
                #     print('exception02, msg = ' + str(msg))
                #     print(e)
                # else:
                # Clean up the connection
                # print('Current connections: ' + str(current_connections) + ' of ' + str(expected_connections) + ' at proc: ' + str(self.roleNumber))
                # if current_connections == expected_connections:
                #     connection.close()
        self.connection_count += expected_connections

    def cleanup(self):
        """
        Clean up resources including thread pools
        """
        log.debug(f"Cleaning up resources at proc: {self.roleNumber}")
        
        # Shutdown send thread pool
        if hasattr(self, 'send_thread_pool'):
            self.send_thread_pool.shutdown(wait=True)
            log.debug(f"Send thread pool shutdown at proc: {self.roleNumber}")
        
        # Shutdown message thread pool
        if hasattr(self, 'message_thread_pool'):
            self.message_thread_pool.shutdown(wait=True)
            log.debug(f"Message thread pool shutdown at proc: {self.roleNumber}")
        
        log.debug(f"Cleanup completed at proc: {self.roleNumber}")

