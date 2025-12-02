import numpy as np
import gmpy2
import time
import sys
from threading import BrokenBarrierError, Lock
import multiprocessing as mp
import logging
import datetime
import os
import pickle
import heapq
import socket
import traceback

# FedTopK imports
from manager import get_ServerManager
from security.elgamal import ElGamal
from security.paillier import Paillier
from mixnet_helper import Mixnet
from messages import paillier_send, elgamal_send, EntryStorage
from communication_helper import CommunicationEnvironment
from mixnet_heap import MixnetSortedList

# import concurrent.futures
# from joblib import Parallel, delayed

rand = gmpy2.random_state(hash(gmpy2.random_state()))

class Worker(CommunicationEnvironment):
    def __init__(self, role_number, role, partition_scheme, security_level, CommEnv, ElGamalInfo=None, PaillierInfo=None, startTime=None):#, bit_len):
        super().__init__(CommEnv.addresses, CommEnv.numberParties, CommEnv.numberWorkers, CommEnv.roles)#, CommEnv.lock)
        self.socket             = None
        self.roleNumber         = role_number
        self.role               = role
        self.partitionScheme    = partition_scheme
        self.security_level     = security_level
        self.queryWeights       = None
        self.k                  = None
        self.thresholdCheck     = False
        self.sendData           = None
        self.topKreturn         = None
        self.CommunicationMB    = 0

        # Communication
        self.connection_count   = 0
        self.exp_connects       = None
        self.RcvStatus          = False
        self.RcvCheck           = 0
        self.checkTA            = True
        self.manager            = None
        self.queue              = None
        self.barrier2           = None
        self.checkID_barrier    = False
        self.checkTA_barrier    = False
        self.countIDs           = 0

        # Security keys
        self.ElGamalInfo        = ElGamalInfo
        self.ElGamalPubKeys     = []  # x & k
        self.PaillierInfo       = PaillierInfo
        self.PaillierPubKeys    = []  # u & s
        # Helper Paillier instance for static-like calls with provided pkey
        self.PaillierHelper     = Paillier(1)

        # Mixnet protocols
        self.batchSize          = None
        self.msg_store          = []
        self.Mixnet             = Mixnet()
        self.compare_vals       = None

        # Multiprocessing
        if self.roleNumber == self.numberParties:
            self.num_process    = 2 # If None, defaults to os.cpu_count(), change to (os.cpu_count() - 1)
        else:
            self.num_process    = 1

        # self.process_pool       = mp.Pool(processes=self.num_process, maxtasksperchild=2)

        # Consistent Random Sum
        self.randNumInit        = 0
        self.randNum_tmp        = 0
        self.randNumInitFlag    = False
        self.u_half             = 0
        self.sum_send_val       = 0
        self.sum_val_noEnc      = 0
        self.sum_val            = [1,1]
        self.PaillierSend       = None
        self.Gamma              = 0

        # Timing/Metrics
        self.startTime          = startTime
        self.numRounds          = 0

        # TA
        if self.security_level == 'secure':
            self.ID_store           = None  # Will be initialized after receiving k
        else:
            self.ID_store           = []
            self.ID_set             = set()
        self.TA                 = None
        
        # Cache queue factories to avoid repeated getattr calls
        self._queue_factories   = {}

    def q(self, index):
        """Return the queue proxy for given index (int or str).
        Uses caching to avoid repeated getattr calls for better performance.
        If the queues dictionary is not yet initialized, try a lazy connect to the manager
        to obtain it. This prevents crashing when code calls q() before explicit
        connect_to_manager() has completed.
        """
        if getattr(self, 'queues', None) is None:
            log.debug(f"queues is None in Worker.q({index}); attempting lazy connect to manager")
            try:
                self.connect_to_manager()
            except Exception as e:
                tb = traceback.format_exc()
                log.debug('Lazy connect_to_manager failed in Worker:')
                log.debug(tb)
                raise RuntimeError("Queue not initialized and lazy connect failed: " + str(e))

        # Use cached queue factory if available
        if index in self._queue_factories:
            return self._queue_factories[index]
            
        try:
            # Cache the queue factory to avoid repeated getattr calls
            queue_factory = getattr(self.manager, f'get_q{index}')
            self._queue_factories[index] = queue_factory
            return queue_factory
        except Exception as e:
            log.debug(f"Failed to return queue factory for index {index} in Worker.q: {e}")
            raise

    def calc_data_size(self, msg):
        """Calculate and accumulate message size for communication metrics.
        Optimized to avoid unnecessary string operations in hot path.
        """
        msg_pickle = pickle.dumps(msg, -1)
        msg_size = len(msg_pickle)
        self.CommunicationMB += msg_size

    def _probe_manager_socket(self, addr):
        """Try to do a simple TCP connect probe to addr if it's a (host, port) tuple.
        Returns (success: bool, msg: str).
        """
        try:
            if isinstance(addr, tuple) and len(addr) == 2:
                host, port = addr
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                try:
                    s.connect((host, int(port)))
                    s.close()
                    return True, f"TCP connect to {host}:{port} succeeded"
                except Exception as e:
                    return False, f"TCP connect to {host}:{port} failed: {e}"
            else:
                return False, f"Address is not a (host, port) tuple: {repr(addr)}"
        except Exception as e:
            return False, f"Probe error: {e}"

    def connect_to_manager(self):
        # Add English debug logs for address and type
        try:
            log.debug('manager address raw = ' + str(self.addresses[-1]) + ' type=' + str(type(self.addresses[-1])))
        except Exception:
            log.debug('manager address not available')

        self.manager = get_ServerManager(self.addresses[-1], self.numberParties, self.numberWorkers, self.role)
        count = 0
        while True:
            try:
                log.debug('Trying to connect to manager, proc: ' + str(self.roleNumber))
                try:
                    # Probe TCP if possible and log result
                    ok, msg = self._probe_manager_socket(self.addresses[-1])
                    # log.debug('Manager socket probe: ' + msg)
                except Exception as e:
                    log.debug('Manager socket probe exception: ' + str(e))

                self.manager.connect()
                # retrieve queues if available
                try:
                    self.queues = self.manager.get_queues()
                    # log.debug('Successfully retrieved queues proxy from manager')
                except Exception as e:
                    log.debug('Failed to retrieve get_queues from manager: ' + str(e))
                # log.debug('Connected to manager, proc: ' + str(self.roleNumber))
                break
            except Exception as e:
                # Log full traceback and a readable message in English
                tb = traceback.format_exc()
                log.debug('Manager connection error:')
                # log.debug(tb)
                # Also include a short human-friendly message
                # log.debug('Could not connect to manager at ' + str(self.addresses[-1]) + ' - retrying in 2s')
                time.sleep(2)
                count += 1
                if count > 30:
                    log.debug('Giving up after 30 retries connecting to manager')
                    raise
        # ...existing code...

    def DistributeKeys(self):
        # Distribute ElGamal public keys
        self.connection_count = 0
        # Receive public encryption keys from other workers
        if self.partitionScheme == 'horizontal':
            self.exp_connects = (self.roleNumber - self.numberParties)
            if self.roleNumber > self.numberParties:
                self.RcvData()          # 2 ElGamal keys

        # elif self.partitionScheme == 'vertical':
        #     self.exp_connects = (self.roleNumber - self.numberParties)
        #     if self.roleNumber > self.numberParties:
        #         self.RcvData() 

        # if self.partitionScheme == 'horizontal':
        #     num_senders = 1
        # elif self.partitionScheme == 'vertical':
        #     num_senders = 1

        num_senders = 1  # Define num_senders for horizontal partition scheme
        
        for role_num in range(self.numberParticipants):
            if role_num != self.roleNumber:
                if self.partitionScheme == 'horizontal':
                    self.SendData(self.roleNumber, role_num, 'EK', self.ElGamalInfo.get_ekey(), False, num_senders)
                elif self.partitionScheme == 'vertical':
                    key_tmp     = self.ElGamalInfo.get_ekey()
                    key_send    = [self.roleNumber, key_tmp.k]
                    # print(f"Sending EK to proc: {role_num} from proc: {self.roleNumber}")
                    # self.SendData(self.roleNumber, role_num, 'EK', key_send, False, num_senders)
                    # Queue replace
                    print(f'Putting EK in queue at proc: {self.roleNumber}')
                    get_queue_fxn_tmp = self.q(role_num)
                    get_queue_fxn_tmp().put([self.roleNumber, 'EK', key_send])
                    self.calc_data_size([self.roleNumber, 'EK', key_send])

                # Last worker messages
                # Distribute Paillier public keys
                if self.roleNumber == (self.numberParticipants - 1):
                    if self.partitionScheme == 'vertical':
                        PaillierSend = paillier_send()
                        PaillierSend.pkey = self.PaillierInfo.get_pkey()
                        # self.SendData(self.roleNumber, role_num, 'PK', PaillierSend, False, num_senders)
                        # Queue replace
                        get_queue_fxn_tmp = self.q(role_num)
                        get_queue_fxn_tmp().put([self.roleNumber, 'PK', PaillierSend])
                        self.calc_data_size(PaillierSend)

                    # Distribute EG.p & EG.g to all parties
                    if role_num < self.numberParties:
                        ElGamal_send = elgamal_send()
                        ElGamal_send.g, ElGamal_send.p = self.ElGamalInfo.g, self.ElGamalInfo.p
                        # self.SendData(self.roleNumber, role_num, 'GP', ElGamal_send, False, num_senders)
                        # Queue replace
                        get_queue_fxn_tmp = self.q(role_num)
                        get_queue_fxn_tmp().put([self.roleNumber, 'GP', ElGamal_send])
                        self.calc_data_size([self.roleNumber, 'GP', ElGamal_send])

        if self.roleNumber == (self.numberParticipants - 1):
            msg_count = self.numberWorkers - 1  # EK from other workers
        else:
            msg_count = self.numberWorkers      # EK (x3), GP, PK

        for rcv_count in range(msg_count):
            get_queue_fxn_tmp = self.q(self.roleNumber)
            msg_rcv = get_queue_fxn_tmp().get()
            msg_from = msg_rcv[0]
            msg_id = msg_rcv[1]
            msg_data = msg_rcv[2]

            # print(f"msg_id = {msg_id} at proc: {self.roleNumber} msg_count = {rcv_count}")

            if msg_id == 'EK':
                self.ElGamalPubKeys.append(msg_data)
            elif msg_id == 'PK':
                self.PaillierPubKeys.append(msg_data)
            elif msg_id == 'GP':
                self.ElGamalInfo = msg_data

    def MultiplicativeMixnet(self, inputMessage):
        return self.Mixnet.MultiplicativeMixnet(self, inputMessage)

    def RefreshMixnet(self, inputMessage):
        return self.Mixnet.RefreshMixnet(self, inputMessage)

    def DecryptionMixnet(self, inputMessage):
        return self.Mixnet.DecryptionMixnet(self, inputMessage)

    def AdditiveMixnetTA(self, inputMessage):
        return self.Mixnet.AdditiveMixnetTA(self, inputMessage)

    def AdditiveMixnet(self, inputMessage):
        return self.Mixnet.AdditiveMixnet(self, inputMessage)

    def ComparativeMixnetID(self, inputMessage):
        # if self.roleNumber != self.numberParties:
        return self.Mixnet.ComparativeMixnetID(self, inputMessage)
        # else:
        #     result = Parallel(n_jobs=2)(delayed(self.Mixnet.ComparativeMixnetID, (self, inputMessage, ), {}))
    def ComparativeMixnetScore(self, inputMessage):
        return self.Mixnet.ComparativeMixnetScore(self, inputMessage)
    
    def ComparativeMixnetScoreBatch(self, inputMessage):
        return self.Mixnet.ComparativeMixnetScoreBatch(self, inputMessage)

    def oddEvenSort(self, data):
        def swap(data, i, j):
            tmp = data[i]
            data[i] = data[j]
            data[j] = tmp
        count = 0
        data_sorted = False
        data_length = len(data)
        while not data_sorted:
            data_sorted = True
            for i in range(1, data_length - 1, 2):
                # Send bit encodings of data
                mult_input  = [data[i].OneEncoding, data[i + 1].ZeroEncoding]
                mix_input   = self.MultiplicativeMixnet(mult_input)
                num_senders = 1
                self.SendData(self.roleNumber, self.roleNumber, 'MM', mix_input, True, num_senders)
                self.connection_count, self.exp_connects = 0, 1
                self.RcvData()
                if self.compare_vals:
                    count += 1
                    swap(data, i, i + 1)
                    data_sorted = False
            for i in range(0, data_length - 1, 2):
                # Send bit encodings of data
                mult_input  = [data[i].OneEncoding, data[i + 1].ZeroEncoding]
                mix_input   = self.MultiplicativeMixnet(mult_input)
                num_senders = 1
                self.SendData(self.roleNumber, self.roleNumber, 'MM', mix_input, True, num_senders)
                self.connection_count, self.exp_connects = 0, 1
                self.RcvData()
                if self.compare_vals:
                    count += 1
                    swap(data, i, i + 1)
                    data_sorted = False
        # log.debug('Number of compares: ' + str(count))
        return data

    #  Deprecated: Use comparativemixnetscore function instead
    def genDistRandNum(self):
        if not self.randNumInitFlag:
            if self.roleNumber == (self.numberParticipants - 1):
                self.PaillierSend        = paillier_send()
                self.PaillierSend.pkey   = self.PaillierInfo.get_pkey()
                self.u_half     = self.PaillierSend.pkey.u // 2 // self.numberWorkers
            else:
                self.u_half     = self.PaillierPubKeys[0].pkey.u // 2 // self.numberWorkers      # Upper half of the largest value it can be without breaking the mod in either encryption scheme
            
            # Generate initial random number
            self.randNumInit        = gmpy2.mpz_random(rand, self.u_half) + self.u_half          # Guarantee it is in the upper half of the possible range...
            self.Gamma              += self.randNumInit

            # Encrypt with Paillier
            if self.roleNumber == (self.numberParticipants - 1):
                r_p                 = Paillier.gen_r(self.PaillierHelper, self.PaillierSend.pkey)
                enc_ele_tmp_p       = Paillier.encrypt(self.PaillierHelper, self.randNumInit, pkey=self.PaillierSend.pkey, r=r_p)
            else:
                r_p                 = Paillier.gen_r(self.PaillierHelper, self.PaillierPubKeys[0].pkey)
                enc_ele_tmp_p       = Paillier.encrypt(self.PaillierHelper, self.randNumInit, pkey=self.PaillierPubKeys[0].pkey, r=r_p)

            # Encrypt with own EG key
            s_1             = gmpy2.mpz_random(rand, self.ElGamalInfo.p) + 1
            gr_s1, m_s1     = ElGamal.encrypt(self.ElGamalInfo, enc_ele_tmp_p, self.ElGamalInfo.k, s_1)

            # Encrypt with other workers keys (if applicable)
            for EGPubKey in self.ElGamalPubKeys:
                if EGPubKey[0] >= self.roleNumber:
                    _, m_s1     = ElGamal.encrypt(self.ElGamalInfo, m_s1, EGPubKey[1], s_1)            

            # Set flag to mark first pass through...
            self.randNumInitFlag    = True

            # Set sum value
            self.sum_val = [gr_s1, m_s1]

            # Send initial number to determine Gamma
            # Change to manager queue (sender puts message in receiver's queue)
            # num_senders = 1
            # self.connection_count = 0
            # self.exp_connects = (self.roleNumber - self.numberParties)
            # if self.roleNumber > self.numberParties:
            #     print('RG rcv at proc: ' + str(self.roleNumber) + ', expected connections: ' + str(self.exp_connects))
            #     self.RcvData()
            #     print('RG rcv broke at proc: ' + str(self.roleNumber))

            # for role_num in range(self.numberParties, self.numberParticipants):
            #     if role_num != self.roleNumber:
            #         print('Sending random number to proc: ' + str(role_num) + ', from ' + str(self.roleNumber))
            #         self.SendData(self.roleNumber, role_num, 'RG', self.randNumInit, False, num_senders)

            # # Receive keys etc
            # self.connection_count = 0
            # self.exp_connects = (self.numberParticipants - self.roleNumber - 1)
            # if self.roleNumber < (self.numberParticipants - 1):
            #     print(f'RG rcv2 at proc: {self.roleNumber}')
            #     self.RcvData()

            for role_num in range(self.numberParties, self.numberParticipants):
                if role_num != self.roleNumber:
                    # self.manager.Queue()
                    get_queue_fxn_tmp = self.q(role_num)#.put([self.roleNumber, 'RG', self.randNumInit])
                    # print(f'num_participants = {self.manager.num_participants}')
                    # print(f'put_rg: {get_queue_fxn_tmp}')
                    # print(f'put_rg: {get_queue_fxn_tmp()}')
                    # log.debug(f'sending to queue at memory address {get_queue_fxn_tmp()}')
                    get_queue_fxn_tmp().put([self.roleNumber, 'RG', self.randNumInit])
                    self.calc_data_size([self.roleNumber, 'RG', self.randNumInit])

            get_queue_fxn_tmp = self.q(self.roleNumber)
            # log.debug(f'reading from queue at memory address {get_queue_fxn_tmp()}')
            rg_rcv = []
            for role_num in range(self.numberParties, self.numberParticipants):
                if role_num != self.roleNumber:
                    self.Gamma += get_queue_fxn_tmp().get()[2]

                    
            if self.roleNumber == (self.numberParticipants - 1):
                log.debug('Gamma = ' + str(self.Gamma) + ' and u = ' + str(self.PaillierSend.pkey.u) + ' and diff = ' + str(self.PaillierSend.pkey.u - self.Gamma) + ' at proc: ' + str(self.roleNumber))
            else:
                log.debug('Gamma = ' + str(self.Gamma))

            # # Send initial number to determine Gamma
            # num_senders = self.numberWorkers

            # for w in range(self.numberParties, self.numberParticipants):
            #     # print('sending to w: ' + str(w) + ', from ' + str(self.roleNumber))
            #     if w != self.roleNumber:
            #         print('Sending random number to proc: ' + str(w) + ', from ' + str(self.roleNumber))
            #         self.SendData(self.roleNumber, w, 'RG', self.randNumInit, False, num_senders)
        else:
            # print('GenDistRandNum else...')
            # Guarantee the newly generated random number will always be less than the initial
            self.randNum_tmp = gmpy2.mpz_random(rand, self.randNumInit - 1) + 1

            # Subtract
            send_CRS_unEnc = self.randNumInit - self.randNum_tmp

            # Set sum_val
            # Encrypt with Paillier
            if self.roleNumber == (self.numberParticipants - 1):
                r_p                 = Paillier.gen_r(self.PaillierHelper, self.PaillierSend.pkey)
                enc_ele_tmp_p       = Paillier.encrypt(self.PaillierHelper, self.randNum_tmp, pkey=self.PaillierSend.pkey, r=r_p)
            else:
                r_p                 = Paillier.gen_r(self.PaillierHelper, self.PaillierPubKeys[0].pkey)
                enc_ele_tmp_p       = Paillier.encrypt(self.PaillierHelper, self.randNum_tmp, pkey=self.PaillierPubKeys[0].pkey, r=r_p)

            # Encrypt with own EG key
            s_1             = gmpy2.mpz_random(rand, self.ElGamalInfo.p) + 1
            gr_s1, m_s1     = ElGamal.encrypt(self.ElGamalInfo, enc_ele_tmp_p, self.ElGamalInfo.k, s_1)

            # Encrypt with other workers keys (if applicable)
            for EGPubKey in self.ElGamalPubKeys:
                if EGPubKey[0] > self.roleNumber:
                    _, m_s1     = ElGamal.encrypt(self.ElGamalInfo, m_s1, EGPubKey[1], s_1)

            # Deprecated: Set sum_val
            sum_val_tmp = [1, 1]
            sum_val_tmp[0], sum_val_tmp[1]      = self.sum_val[0] * gr_s1, self.sum_val[1] * m_s1
            self.sum_val[0], self.sum_val[1]    = gmpy2.f_mod(sum_val_tmp[0], self.ElGamalInfo.p), gmpy2.f_mod(sum_val_tmp[1], self.ElGamalInfo.p)

            # Unencrypted check
            self.sum_val_noEnc  += self.randNum_tmp

            # Set send sum val (difference)
            # Encrypt with Paillier
            if self.roleNumber == (self.numberParticipants - 1):
                # print('Proc: ' + str(self.roleNumber) + ' encrypting with P1 key')
                r_p2                 = Paillier.gen_r(self.PaillierHelper, self.PaillierSend.pkey)
                enc_ele_tmp_p2       = Paillier.encrypt(self.PaillierHelper, send_CRS_unEnc, pkey=self.PaillierSend.pkey, r=r_p2)
            else:
                # print('Proc: ' + str(self.roleNumber) + ' encrypting with P2 key')
                r_p2                 = Paillier.gen_r(self.PaillierHelper, self.PaillierPubKeys[0].pkey)
                enc_ele_tmp_p2       = Paillier.encrypt(self.PaillierHelper, send_CRS_unEnc, pkey=self.PaillierPubKeys[0].pkey, r=r_p2)

            # Encrypt with other workers keys
            s_2             = gmpy2.mpz_random(rand, self.ElGamalInfo.p) + 1
            m_s2            = enc_ele_tmp_p2
            for EGPubKey in self.ElGamalPubKeys:
                if self.roleNumber == (self.numberParticipants - 1):
                    # Last worker encrypts with all EG keys
                    gr_s2, m_s2         = ElGamal.encrypt(self.ElGamalInfo, m_s2, EGPubKey[1], s_2)
                else:
                    # Other workers encrypt with EG keys from workers later in mixnet chain than them
                    if EGPubKey[0] > self.roleNumber:
                        gr_s2, m_s2     = ElGamal.encrypt(self.ElGamalInfo, m_s2, EGPubKey[1], s_2)

            # Last worker encrypt with own EG key
            if self.roleNumber == (self.numberParticipants - 1):
                gr_s2, m_s2     = ElGamal.encrypt(self.ElGamalInfo, m_s2, self.ElGamalInfo.k, s_2)

            # Store send value...
            self.sum_send_val = [gr_s2, m_s2, send_CRS_unEnc]

            # Send updated random number to next worker in chain...
            # Change to manager queue (sender puts message in receiver's queue)
            num_senders = 1

            if self.roleNumber == (self.numberParticipants - 1):
                destination_role_number = self.roles.index('moderator')
                # print(f'Sending RS at proc {self.roleNumber} to proc {destination_role_number}')
                self.SendData(self.roleNumber, destination_role_number, 'RS', self.sum_send_val, False, num_senders)
            else:
                # print(f'Sending RS at proc {self.roleNumber} to proc {self.roleNumber + 1}')
                self.SendData(self.roleNumber, self.roleNumber + 1, 'RS', self.sum_send_val, False, num_senders)

    def ProcessLoop(self):#barrier, barrier2, barrier3, barrier4, event):
        # Key Gen
        if self.security_level == 'secure':
            self.ElGamalInfo.key_gen()

        # Initialize socket connection
        self.connect_to_manager()
        self.SetupSocket()#barrier)

        # Distribute public keys
        if self.security_level == 'secure':
            self.DistributeKeys()

        # Wait for all parties/workers to get to this point
        try:
            # log.debug('Waiting at key barrier proc: ' + str(self.roleNumber))
            self.manager.wait0().wait()#barrier2.wait()
        except BrokenBarrierError:
            pass

        # Connect/key exchange time
        elapsed_time = round(time.time() - self.startTime, 5)
        log.debug(f'Elapsed time KEY/SETUP: {elapsed_time}')

        # Receive query weights
        # self.connection_count, self.exp_connects = 0, 1
        # self.RcvData()
        get_queue_fxn_tmp = self.q(self.roleNumber)
        msg_rcv = get_queue_fxn_tmp().get()

        msg_from = msg_rcv[0]
        msg_id = msg_rcv[1]
        msg_data = msg_rcv[2]

        if msg_id == 'QW':
            self.queryWeights   = msg_data[0]
            self.k              = msg_data[1]
            # log.debug('k = ' + str(self.k))
            
            # Initialize ID_store now that we have k
            if self.security_level == 'secure' and self.ID_store is None:
                self.ID_store = MixnetSortedList(self, self.k)  
    
        # log.debug('Query weights rcv at proc: ' + str(self.roleNumber))

        if self.partitionScheme == 'horizontal':
            self.batchSize = self.k * self.numberParties    # Batch size equals k * m (all returned values)
            # Wait for all parties/workers to get to this point
            try:
                # log.debug('Waiting at entry barrier, proc: ' + str(self.roleNumber))
                self.manager.wait0().wait()#barrier2.wait()
                # log.debug('Entry barrier broken, proc: ' + str(self.roleNumber))
            except BrokenBarrierError:
                pass
            # Moderator receive encrypted values (mixnet refresh round)
            if self.role == 'moderator':
                self.connection_count, self.exp_connects = 0, self.numberParties + 1
            # last worker in mixnet
            elif self.roleNumber == (self.numberParticipants - 1):
                self.connection_count, self.exp_connects = 0, 1
            else:
                self.connection_count, self.exp_connects = 0, 1
            self.RcvData()

            # Moderator has all data after refresh round
            if self.role == 'moderator':
                self.topKreturn     = self.oddEvenSort(self.aggregateTopK[0])

                # Select top-k, decryption round to return to parties...
                query_return = []
                for ind in range(0, self.k):
                    query_return.append(self.topKreturn[-(ind + 1)].ID)
                mix_input       = self.DecryptionMixnet(query_return)
                num_senders     = 1
                self.SendData(self.roleNumber, 0, 'QR', mix_input, True, num_senders)
            else:
                self.RcvStatus = True
                while self.RcvStatus:
                    self.connection_count, self.exp_connects = 0, 1
                    self.RcvData()
        elif self.partitionScheme == 'vertical':
            # Wait for all parties/workers to get to this point
            try:
                # log.debug('Waiting at post QW barrier, proc: ' + str(self.roleNumber))
                self.manager.wait0().wait()#barrier2.wait()
                # log.debug('QW barrier broken at proc: ' + str(self.roleNumber))
            except BrokenBarrierError:
                pass

            # Query weight exchange time
            elapsed_time = round(time.time() - self.startTime, 5)
            log.debug(f'Elapsed time QW: {elapsed_time}')

            # Initialize consistent random sum
            # if self.security_level == 'secure':
                # Generate random number
                # self.genDistRandNum()

                # Wait for all parties/workers to get to this point
                # try:
                    # log.debug('Waiting at post-GenDistRandNum proc: ' + str(self.roleNumber))
                    # self.manager.wait0().wait()#barrier2.wait()
                # except BrokenBarrierError:
                    # pass

                # Connect/key exchange time
                # elapsed_time = round(time.time() - self.startTime, 5)
                # log.debug(f'Elapsed time GenDistRandNum: {elapsed_time}')

            log.debug('Workers entered algo at proc: ' + str(self.roleNumber))

            # Moderator process loop
            if self.role == 'moderator':
                # self.manager = manager
                # self.barrier2 = barrier2
                # self.barrier3 = barrier3
                self.batchSize = self.numberParties
                while True:
                    self.RcvStatus = True
                    # Rcv TA from parties
                    # for p in range(self.numberParties + 1):
                    #     self.connection_count, self.exp_connects = 0, 1
                    #     self.RcvData()
                        # get_queue_fxn_tmp = getattr(self.manager, 'get_q' + str(self.roleNumber))
                        # msg_rcv = get_queue_fxn_tmp().get()
                        # msg_from = msg_rcv[0]
                        # msg_id = msg_rcv[1]
                        # msg_data = msg_rcv[2]

                        # print(f'msg_id = {msg_id}')

                        # if msg_id == 'TA':
                        #     for msg_tmp in msg_data:
                        #         self.msg_store.append(msg_tmp)

                        #     if len(self.msg_store) >= self.batchSize:
                        #         if self.security_level == 'secure':
                        #             mix_msg_data = self.AdditiveMixnetTA(self.msg_store)
                        #         elif self.security_level == 'nonsecure':
                        #             # Sum input values
                        #             sum_val = 0
                        #             for msg in self.msg_store:
                        #                 sum_val += msg.value
                        #             mix_msg_data = sum_val
                        #         num_senders = 1
                        #         # self.SendData(self.roleNumber, self.roleNumber + 1, 'TA', mix_msg_data, True, num_senders)
                        #         get_queue_fxn_tmp = getattr(self.manager, 'get_q' + str(self.roleNumber + 1))
                        #         get_queue_fxn_tmp().put([self.roleNumber, 'TA', mix_msg_data])
                        #         self.msg_store = []
                        #         self.sum_val = [1, 1]
                        #         # print('sum_val = ' + str(self.sum_val) + ' at proc: ' + str(self.roleNumber))
                        #         self.sum_val_noEnc = 0
                        #         # self.genDistRandNum()
                        # elif msg_id == 'TM':
                        #     # print('Msg: TM, proc: ' + str(self.roleNumber))
                        #     test_sum = 0
                        #     if self.security_level == 'secure':
                        #         for msg_tmp in msg_data:
                        #             # print('TM')
                        #             # print(msg_tmp.ID)
                        #             if msg_tmp.ID == 'TA':
                        #                 self.TA = msg_tmp.encValue
                        #                 log.debug('TA = ' + str(self.TA))
                        #             else:
                        #                 # self.ID_store.append(msg_tmp)
                        #                 # print(self.ID_store)
                        #                 test_sum += msg_tmp.value
                        #                 # print('msg value: ' + str(msg_tmp.value))
                        #     elif self.security_level == 'nonsecure':
                        #         log.debug(msg_data)
                        #         self.TA = msg_data

                            # if self.security_level == 'secure':
                            #     # Send and receive RS
                            #     self.genDistRandNum()
                            #     self.connection_count, self.exp_connects = 0, 1
                            #     self.RcvData()

                            # # Wait after TA
                            # try:
                            #     log.debug('waiting at proc after TA: ' + str(self.roleNumber))
                            #     # print(self.barrier2.parties)
                            #     # print(self.barrier2.n_waiting)
                            #     self.manager.wait1().wait()#self.barrier3.wait()
                            #     self.checkID_barrier    = False
                            #     self.checkTA_barrier    = False
                            #     self.countIDs           = 0
                            #     # self.barrier2.reset()
                            # except BrokenBarrierError:
                            #     log.debug('barrier3 err')
                            #     pass
                    print(f"self.RcvStatus = {self.RcvStatus} and self.checkTA = {self.checkTA}")
                    while self.RcvStatus and self.checkTA:
                        self.connection_count, self.exp_connects = 0, 1
                        self.RcvData()

                    # Step 4, check scores against threshold
                    # kCount = 0)

   
                    if self.thresholdCheck and self.security_level == 'secure':
                        query_return = self.ID_store.get_top_k()
                    elif self.thresholdCheck and self.security_level == 'nonsecure':
                        query_return = self.ID_store[:self.k]
                    else:
                        query_return = []
 
                    # for entry_tmp in comp_vals: #self.aggregateTopK[unique_inds]:
                        # print('compare to k vals')
                        # log.debug(f'ID = {entry_tmp.noEncID}, val - Gamma = {entry_tmp.encValue - self.Gamma}, TA - Gamma = {self.TA - self.Gamma}')
                        # if entry_tmp.encValue > self.TA: # - self.Gamma:
                        #     kCount += 1

                    # Distribute query return or repeat algorithm
                    num_senders = 1
                    if len(query_return) == 0:
                        for p in range(self.numberParties):
                            # self.SendData(self.roleNumber, p, 'TR', [], False, num_senders)
                            # Queue replace
                            get_queue_fxn_tmp = self.q(p)
                            get_queue_fxn_tmp().put([self.roleNumber, 'TR', []])
                            self.calc_data_size([self.roleNumber, 'TR', []])
                        self.checkTA = True
                        self.numRounds += 1
                    else:
                        # self.aggregateTopK.sort(reverse=True)
                        query_return_IDs    = []

                        for entry in query_return: #self.aggregateTopK:
                            if self.security_level == 'secure':
                                query_return_IDs.append(entry.ID)
                            elif self.security_level == 'nonsecure':
                                query_return_IDs.append(entry.noEncID)
                        num_senders = 1
                        
                        if self.security_level == 'secure':
                            mix_query_return = self.DecryptionMixnet(query_return_IDs)
                        elif self.security_level == 'nonsecure':
                            mix_query_return = query_return_IDs
                        self.SendData(self.roleNumber, 0, 'QR', mix_query_return, True, num_senders) # Will send to all parties...
                        break
                    log.debug('Moderator begining next round...')
            else:
                # # Queue TA rcv
                # get_queue_fxn_tmp = getattr(self.manager, 'get_q' + str(self.roleNumber))
                # msg_rcv = get_queue_fxn_tmp().get()
                # msg_from = msg_rcv[0]
                # msg_id = msg_rcv[1]
                # msg_data = msg_rcv[2]

                # print(f'msg_id = {msg_id}')

                # if msg_id == 'TA':
                #     if self.roleNumber < (self.numberParticipants - 1) and self.roleNumber > self.numberParties:
                #         if self.security_level == 'secure':
                #             mix_msg_data = self.AdditiveMixnetTA(msg_data)
                #         elif self.security_level == 'nonsecure':
                #             mix_msg_data = msg_data
                #         num_senders = 1
                #         print(f"Sending TA opt 2q at proc: {self.roleNumber}")
                #         # self.SendData(self.roleNumber, self.roleNumber + 1, 'TA', mix_msg_data, True, num_senders)
                #         get_queue_fxn_tmp = getattr(self.manager, 'get_q' + str(self.roleNumber + 1))
                #         get_queue_fxn_tmp().put([self.roleNumber, 'TA', mix_msg_data])
                #         self.sum_val = [1, 1]
                #         # print('sum_val = ' + str(self.sum_val) + ' at proc: ' + str(self.roleNumber))
                #         self.sum_val_noEnc = 0
                #         # self.genDistRandNum()
                #     # If last worker, send to moderator...
                #     elif self.roleNumber == (self.numberParticipants - 1):
                #         if self.security_level == 'secure':
                #             mix_msg_data = self.AdditiveMixnetTA(msg_data)
                #         elif self.security_level == 'nonsecure':
                #             mix_msg_data = msg_data
                #         num_senders             = 1
                #         destination_role_number = self.roles.index('moderator')
                #         print(f"Sending TM opt 3 at proc: {self.roleNumber}")
                #         # self.SendData(self.roleNumber, destination_role_number, 'TM', mix_msg_data, True, num_senders)
                #         get_queue_fxn_tmp = getattr(self.manager, 'get_q' + str(destination_role_number))
                #         get_queue_fxn_tmp().put([self.roleNumber, 'TM', mix_msg_data])
                #         self.sum_val = [1, 1]
                #         # print('sum_val = ' + str(self.sum_val) + ' at proc: ' + str(self.roleNumber))
                #         self.sum_val_noEnc = 0
                #     # else:
                #         # self.aggregateTopK.append(msg_data)
                print(f"Rcv status before while loop at proc: {self.roleNumber}")
                self.RcvStatus = True
                while self.RcvStatus:
                    self.connection_count, self.exp_connects = 0, 1
                    self.RcvData()
                # log.debug('Rcv broke at proc: ' + str(self.roleNumber))

        # Print end time
        if self.role == 'moderator':
            log.debug("--- %s seconds ---" % (time.time() - self.startTime))
            log.debug('Number of TA rounds required: ' + str(self.numRounds))
        else:
            log.debug('Worker: ' + str(self.roleNumber) + ', finished process loop!')

        log.debug('Proc ' + str(self.roleNumber) + ' sent ' + str(self.CommunicationMB) + ' total bytes of data')
        
        # Clean up TA thread pool resources
        if hasattr(self, 'cleanup_ta_thread_pool'):
            self.cleanup_ta_thread_pool()

        if self.roleNumber == (self.numberParticipants - 1):
            self.manager.set().set()
        
        # Clean up resources
        self.cleanup()
        log.debug('Proc ' + str(self.roleNumber) + ' has terminated')


def setupWorker(unitTest=False):
    # Start time
    start_time = time.time()
    start_time = time.time()

    # try:
    # Handle inputs (add partitioning scheme and security level...)
    dataset          = sys.argv[1]
    norm_type        = sys.argv[2]
    query_weights_in = sys.argv[3]
    k_in             = sys.argv[4]
    num_parties      = int(sys.argv[5])
    num_workers      = int(sys.argv[6])
    partition_scheme = sys.argv[7]
    security_level   = sys.argv[8]
    role_number      = int(sys.argv[9])
    address_list     = sys.argv[10]
    log.debug('Worker set using inputs...')
    # except:
    #     print('Using default inputs...')
    #     dataset          = 'wine_quality'
    #     query_weights_in = '1, 1, 1, 1, 1, 1, 1, 1, 1'
    #     k_in             = '4'
    #     num_parties      = 3
    #     num_workers      = 3
    #     partition_scheme = 'vertical'
    #     security_level   = 'secure'
    #     role_number      = num_parties

    # Check for and remove added comma
    # if ',' in k_in:
    #     k_in = k_in[:-1]

    # # Parse query weights
    # query_weights = []

    # for i in query_weights_in.split(', '):
    #     query_weights.append(float(i))

    # Initialize party inputs
    num_participants    = num_parties + num_workers
    role_numbers        = list(range(num_participants))

    # Setup comm environment inputs
    allAddresses    = []
    roles           = []
    address_roots   = []
    
    for address in address_list.split(','):
        address_roots.append(address)
    # print('address_roots' + str(address_roots))
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
    add_tmp = (address_roots[-1], manager_root + (part - num_participants))
    role_tmp = 'manager'
    allAddresses.append(add_tmp)
    roles.append(role_tmp)

    # Initialize query
    # QueryWeights    = np.array(query_weights)
    k               = int(k_in)

    # Define security environment
    e_key_len   = 256                         # NIST recommended: 224  (160 for compare to SECYAN)
    e_bit_len   = 3072                        # NIST recommended: 2048 (1024 for compare to SECYAN)

    if security_level == 'secure':
        # Generate EG info for each worker
        eg_worker_info = []
        for w in range(num_workers):
            eg_worker_info.append(ElGamal(e_key_len, e_bit_len))

        if partition_scheme == 'vertical':
            # Add check on Paillier group length
            p_bit_len   = int(np.sqrt(2048))
            pa01        = Paillier(p_bit_len)
            count       = 0
            eg_p        = eg_worker_info[0].p

            while True:
                pa01.key_gen()
                pa_lim = pa01.usquare ** (num_parties + (3 * num_workers))
                if ((num_parties + (2 * num_workers)) * pa01.usquare) < eg_p:
                    ratio01 = (num_parties + 1) * pa01.usquare / eg_p
                    ratio02 = (pa01.usquare ** (num_parties + 1)) / eg_p
                    break
                elif count == 10:
                    break
                log.debug('key gen count: ' + str(count))
                count += 1

    # Initialize communication envrionment
    # lock = Lock()                   # This will likely not scale well to distributed system...
    CE   = CommunicationEnvironment(allAddresses, num_parties, num_workers, roles)#, lock)

    # Specify data location and partitions
    if dataset == 'raisin':
        file_path = './raisin_preprocess_norm_l1.csv'
    elif dataset == 'housing':
        file_path = './housing_preprocess_norm_l1.csv'
    elif dataset == 'dry_bean':
        file_path = './drybean_preprocess_norm_l1.csv'
    elif dataset == 'wine_quality':
        file_path = './winequality_preprocess_norm_l1.csv'
    elif dataset == 'shuttle':
        file_path = './shuttle_preprocess_norm_l1.csv'

    # Check output top-k IDs
    # cols            = list(pd.read_csv(file_path, nrows = 1))
    # data_series_tmp = pd.read_csv(file_path)
    # data_series_tmp.index += 1
    # scores_tmp      = data_series_tmp * QueryWeights
    # db_len          = len(scores_tmp)

    # expected_scores = scores_tmp.sum(axis=1).sort_values(ascending=False)[:k]
    # expected_ids    = list(expected_scores.index)
    # print(expected_scores)
    # print(expected_ids)

    # Initialize parties (Inputs: Role number, role, partition scheme, communication environment)
    # if role_number < num_parties:
    # if role_number == 1:
    #     partyRole = Party(role_numbers[role_number], roles[role_number], partition_scheme, security_level, CE, QueryWeights, k, startTime = start_time)
    # else:
    #     partyRole = Party(role_numbers[role_number], roles[role_number], partition_scheme, security_level, CE, startTime = start_time)
    # if security_level == 'secure':
    #     partyRole.set_pir_params(db_len, e_bit_len)
    # else:
    # If statement really only applies in vertical case...
    eg_count            = 0         # Need to change...
    if role_number == (num_participants - 1):
        if partition_scheme == 'horizontal':
            worker_role = Worker(role_numbers[role_number], roles[role_number], partition_scheme, security_level, CE, eg_worker_info[eg_count], startTime = start_time)
        elif partition_scheme == 'vertical':
            # Include Paillier key at moderator in vertical setup
            if security_level == 'secure':
                worker_role = Worker(role_numbers[role_number], roles[role_number], partition_scheme, security_level, CE, eg_worker_info[eg_count], pa01, startTime = start_time)
            elif security_level == 'nonsecure':
                worker_role = Worker(role_numbers[role_number], roles[role_number], partition_scheme, security_level, CE, startTime = start_time)
    else:
        if security_level == 'secure':
            worker_role = Worker(role_numbers[role_number], roles[role_number], partition_scheme, security_level, CE, eg_worker_info[eg_count], startTime = start_time)
        elif security_level == 'nonsecure':
            worker_role = Worker(role_numbers[role_number], roles[role_number], partition_scheme, security_level, CE, startTime = start_time)

    # Create multiprocessing
    if not unitTest:
        # barrier     = mp.Barrier(num_participants + 1) # All participants + main thread....
        # barrier2    = mp.Barrier(num_participants)     # All participants
        # barrier3    = mp.Barrier(num_participants - (num_workers - 1)) # All parties and one mixnet worker (moderator)
        # barrier4    = mp.Barrier(num_parties)
        # event       = mp.Event()

        # Execute protocol
        worker_role.ProcessLoop()#barrier, barrier2, barrier3, barrier4, event)
    else:
        return worker_role

if __name__ == '__main__':
    # log = logging.getLogger(f'role_{sys.argv[8]}')
    log = logging.getLogger('fedtopk')
    log.setLevel('DEBUG')
    t = datetime.datetime.now()
    if not os.path.exists('runtime/logging'): # Config file, log path
        os.makedirs('runtime/logging')
    time_format = "%Y%m%d%T%H%M%S"

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt=time_format)
    fh = logging.FileHandler(filename=f'runtime/logging/role_{sys.argv[8]}_{t.strftime("TY%d%m%T%H%M%S")}.log')
    fh.setFormatter(formatter)
    log.addHandler(fh)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    log.addHandler(console)

    setupWorker()
