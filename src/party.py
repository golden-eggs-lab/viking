import numpy as np
import pandas as pd
import sys
import time
import random
from communication_helper import CommunicationEnvironment
from threading import BrokenBarrierError, Lock
import pickle
import gmpy2
import multiprocessing as mp
import logging
import datetime
import os
import pickle
import socket
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed

# FedTopK Imports
from security.elgamal import ElGamal
from security.paillier import Paillier
from bit_compare import Encoding
from time import sleep
from sealpir import SealPIR, PirParams
import seal
import sealp
from manager import get_ServerManager
from messages import paillier_send, elgamal_send, EntryStorage

picklingFlag = False


def binary_to_uint8(party_obj, bytestring, db_enc):
    # top_ten             = party_obj.scores[:15].index
    expected_byte_len   = len(bytestring) - 2
    # print(expected_byte_len)
    byte_tmp            = []
    for byte in range(expected_byte_len):
        db_enc.append(bytestring[byte + 2])
        byte_tmp.append(bytestring[byte + 2])

    while expected_byte_len < 384: #256: # ElGamal bit length // 8
        # If byte length 255 (add 0 in front)
        db_enc.append(0)
        byte_tmp.append(0)
        expected_byte_len = len(byte_tmp)

    py_bytes = list(bytestring[2:])
    if len(py_bytes) < 384: #256: # ElGamal bit length // 8
        py_bytes.append(0)

    return db_enc


class objOT():
    def __init__(self):
        self.pubKey         = None
        self.partyOfOrigin  = None

class objSS_OT():
    def __init__(self):
        self.query          = None
        self.partyOfOrigin  = None
        self.newIdFlag      = None
        self.select_inds    = None

class objSR_OT():
    def __init__(self):
        self.reply          = None
        self.partyOfOrigin  = None

class Party(CommunicationEnvironment):
    def __init__(self, role_number, role, partition_scheme, security_level, CommEnv, norm_type, query_weights=None, k_param=None, startTime=None, expected_answer=None):
        super().__init__(CommEnv.addresses, CommEnv.numberParties, CommEnv.numberWorkers, CommEnv.roles)#, CommEnv.lock)
        self.socket             = None
        self.moderatorInd       = 1
        self.roleNumber         = role_number
        self.role               = role
        self.partitionScheme    = partition_scheme
        self.expected_answer    = expected_answer
        self.security_level     = security_level
        self.norm_type          = norm_type
        self.queryWeights       = query_weights
        self.k                  = k_param
        self.data               = None
        self.aggregateTopK      = []
        self.scores             = None
        self.scoresOT           = None
        self.topKreturn         = None
        self.readColInds        = None
        self.terminateTA        = False
        self.sumID              = None
        self.currentIDsum       = [1,1]
        self.currentIDsumInvert = [1,1]
        self.countSR            = 0
        self.checkTA            = True
        self.storeSR            = []
        self.randNumInit_flag   = False

        # Communication
        self.connection_count   = 0
        self.exp_connects       = None
        self.RcvStatus          = False
        self.RcvCheck           = 0
        self.Encoding           = Encoding()
        self.CommunicationMB    = 0
        self.startTime          = startTime
        self.newIdFlag          = False
        self.manager            = None
        self.queue              = None
        self.barrier2           = None
        self.pubKeysPIRdict     = {}
        self.enc_params         = None
        self.pir_params         = None
        self.pir_client         = None
        self.pir_server         = None
        self.pir_queries        = []
        self.pir_send_replies   = []
        self.pir_offset         = None
        self.db_len             = 0
        self.e_bit_len          = 0
        self.galois_keys        = None
        self.galois_keys_bytes  = None
        self.db_enc             = []
        self.db_enc_pair        = []
        # self.initFlag           = False

        # Security keys
        self.ElGamalInfo        = None
        self.ElGamalPubKeys     = []  # x & k
        self.PaillierInfo       = None
        self.PaillierPubKeys    = []  # u & s
        # Helper Paillier instance for static-like calls with provided pkey
        self.PaillierHelper     = Paillier(1)

        # Multiprocessing
        if self.roleNumber == (self.numberParties - 1):
            self.num_process    = 2 # If None, defaults to os.cpu_count(), change to (os.cpu_count() - 1)?
        else:
            self.num_process    = 1
        # self.process_pool       = mp.Pool(processes=self.num_process, maxtasksperchild=2)

        # Not used
        self.sendData           = None
        self.sortedAccessInd    = 0
        
        # Cache queue factories to avoid repeated getattr calls
        self._queue_factories   = {}
        # Cache queue proxies to avoid repeated factory() calls
        self._queue_proxies     = {}
        # Reusable IO executor for queue puts to avoid per-round threadpool creation
        io_workers = min(8, os.cpu_count())
        self.io_executor = ThreadPoolExecutor(max_workers=io_workers)

    def q(self, index):
        """Return the queue proxy for given index (int or str).
        Uses caching to avoid repeated getattr calls for better performance.
        If the queues dictionary is not yet initialized, try a lazy connect to the manager
        to obtain it. This prevents crashing when code calls q() before explicit
        connect_to_manager() has completed.
        """
        if getattr(self, 'queues', None) is None:
            log.debug(f"queues is None in q({index}); attempting lazy connect to manager")
            try:
                # Try to (re)connect; connect_to_manager contains its own retry logic
                self.connect_to_manager()
            except Exception as e:
                tb = traceback.format_exc()
                log.debug('Lazy connect_to_manager failed:')
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
            log.debug(f"Failed to return queue factory for index {index}: {e}")
            raise

    def qp(self, index):
        """Return and cache the queue proxy for given index for faster IO."""
        if index in self._queue_proxies:
            return self._queue_proxies[index]
        queue_factory = self.q(index)
        proxy = queue_factory()
        self._queue_proxies[index] = proxy
        return proxy

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
                    ok, msg = self._probe_manager_socket(self.addresses[-1])
                    log.debug('Manager socket probe: ' + msg)
                except Exception as e:
                    log.debug('Manager socket probe exception: ' + str(e))

                self.manager.connect()
                try:
                    self.queues = self.manager.get_queues()
                    log.debug('Successfully retrieved queues proxy from manager')
                except Exception as e:
                    log.debug('Failed to retrieve get_queues from manager: ' + str(e))
                log.debug('Connected to manager, proc: ' + str(self.roleNumber))
                break
            except Exception as e:
                tb = traceback.format_exc()
                log.debug('Manager connection error:')
                log.debug(tb)
                log.debug('Could not connect to manager at ' + str(self.addresses[-1]) + ' - retrying in 2s')
                time.sleep(2)
                count += 1
                if count > 30:
                    log.debug('Giving up after 30 retries connecting to manager')
                    raise
        # ...existing code...

    def set_pir_params(self, db_len, e_bit_len):
        self.db_len     = db_len
        self.e_bit_len  = e_bit_len

    def pir_init(self):
        # Generate PIR parameters
        # self.enc_params, self.pir_params = SealPIR.gen_pir_params(self.db_len, self.e_bit_len)
        self.enc_params, self.pir_params = SealPIR.gen_pir_params(self.db_len, 2 * self.e_bit_len)

        # Print parameters
        # sealp.print_seal_params(self.enc_params)
        # sealp.print_pir_params(self.pir_params)

        # Initialize each party as client & server for PIR communications
        self.pir_client = sealp.PIRClient(self.enc_params, self.pir_params)
        self.pir_server = sealp.PIRServer(self.enc_params, self.pir_params)
        self.galois_keys = self.pir_client.generate_galois_keys()

        # Would simplify protocol (no file write/read) but seal.Serializable not included in module...
        # serialize/deserialize galois keys included in sealp module but see above line
        # print(sealp.serialize_galoiskeys(seal.Serializable(self.galois_keys)))
        # print(sealp.deserialize_galoiskeys())

        # Save Galois keys to '.bin' file for each party
        # gk_file_name = '/mnt/efs/fs1/FedTopK_Dev_working/src/tmp_galois_keys/gk' + str(self.roleNumber) + '.bin'
        gk_file_name = './src/tmp_galois_keys/gk' + str(self.roleNumber) + '.bin'
        self.galois_keys.save(gk_file_name)

        # Read file name to save galois keys as bytes
        with open(gk_file_name, mode='rb') as file: # b is important -> binary
            self.galois_keys_bytes = file.read()

    def pir_encrypt_database(self, database_input=None):
        # Initialize encrypted db
        db_enc      = []
        db_enc_pair = []

        try:
            if database_input == None:
                database    = self.scoresOT.astype('int')
            else:
                database    = database_input
        except:
            database        = database_input

        for value in database:
            enc_ele_tmp     = gmpy2.mpz(value)

            # Encrypt with Paillier
            r_p             = Paillier.gen_r(self.PaillierHelper, self.PaillierPubKeys[0].pkey)
            enc_ele_tmp_p   = Paillier.encrypt(self.PaillierHelper, enc_ele_tmp, pkey=self.PaillierPubKeys[0].pkey, r=r_p)
            enc_ele_tmp_p_inv = gmpy2.invert(enc_ele_tmp_p, gmpy2.mpz(self.PaillierPubKeys[0].pkey.usquare))
            # Inputs: encrypt(self, v, pkey=None, r=None
            r_party             = ElGamal.gen_r(self.ElGamalInfo)
            enc_ele = enc_ele_tmp_p
            
            r_party_inv = ElGamal.gen_r(self.ElGamalInfo)
            enc_ele_inv = enc_ele_tmp_p_inv

            for w in range(self.numberWorkers):
                ene_ele_r, enc_ele    = ElGamal.encrypt(self.ElGamalInfo, enc_ele, self.ElGamalPubKeys[w][1], r_party)
                ene_ele_r_inv, enc_ele_inv    = ElGamal.encrypt(self.ElGamalInfo, enc_ele_inv, self.ElGamalPubKeys[w][1], r_party_inv)
            enc_val_out         = [ene_ele_r, enc_ele, ene_ele_r_inv, enc_ele_inv]
            db_enc_pair.append(enc_val_out)

            # Save encrypted pair to encrypted db
            for comp in enc_val_out:
                bin_tmp = gmpy2.to_binary(comp)
                db_enc = binary_to_uint8(self, bin_tmp, db_enc)
        self.db_enc = db_enc

        try:
            if database_input == None:
                return db_enc_pair
        except:
            return self.db_enc

    # Convert pir values to encrypted pair
    def pir_to_encrypted_pair(self, elems):
        # print('elems type: ' + str(type(elems)))
        byte_tmp    = bytearray(elems)
        b_tmp       = bytearray(b'\x01\x01')

        chunk_size  = self.e_bit_len // 8
        # print('chunk_size = ' + str(chunk_size))
        chunks = [byte_tmp[i*chunk_size:(i+1)*chunk_size] for i in range(4)]

        outs = []
        for chunk in chunks:
            if chunk[-1] == 0:
                chunk = chunk[:-1]
            chunk[0:0] = b_tmp
            outs.append(gmpy2.from_binary(bytes(chunk)))

        c = [outs[0], outs[1]]
        c_inv = [outs[2], outs[3]]
        return c, c_inv

    def ReadDataHorizontal(self, file_location, row_numbers):
        cols            = list(pd.read_csv(file_location, nrows = 1))
        start_ind       = row_numbers[0] + 1        # Offset for starting at 1? (not sure but agrees with output when reading all data in...)
        row_count       = len(row_numbers)
        row_ID          = row_numbers
        keep_cols       = []
        for i in cols:
            if i != 'ocean_proximity' and i != 'Class':
                # print(i)
                keep_cols.append(i)
        data_series_tmp = pd.read_csv(file_location, skiprows = range(1,start_ind), nrows = row_count, usecols = keep_cols) #[i for i in cols if i != 'ocean_proximity' if i != 'Class'])
        data_series_tmp = data_series_tmp.set_axis(row_ID)
        self.data       = data_series_tmp

    def ReadDataVertical(self, file_location):
        cols            = list(pd.read_csv(file_location, nrows = 1))
        cols_use        = cols #[i for i in cols if i != 'Class']
        num_cols        = len(cols_use)

        # Divide columns by parties
        # First party
        if self.roleNumber == 0:
            col_ind             = int(num_cols * ((self.roleNumber + 1) / self.numberParties))
            read_cols           = cols_use[:col_ind]
            self.readColInds    = [0, col_ind]
        # Parties in the middle
        elif self.roleNumber > 0 and self.roleNumber < (self.numberParties - 1):
            col_ind_start       = int(num_cols * ((self.roleNumber) / self.numberParties))
            col_ind_end         = int(num_cols * ((self.roleNumber + 1) / self.numberParties))
            read_cols           = cols_use[col_ind_start:col_ind_end]
            self.readColInds    = [col_ind_start, col_ind_end]
        # Last party
        else:
            col_ind_start       = int(num_cols * ((self.roleNumber) / self.numberParties))
            read_cols           = cols_use[col_ind_start:]
            self.readColInds    = [col_ind_start, num_cols]

        # Read-in data columns
        data_series_tmp = pd.read_csv(file_location, usecols = [i for i in read_cols], sep = ',')
        self.data       = data_series_tmp
        # print('Data shape: ' + str(self.data.shape))

    def CalculateScores(self):
        if self.partitionScheme == 'horizontal':
            # Calculates score for each tuple then sorts all tuple scores
            scores_tmp  = self.data * self.queryWeights
            self.scores = scores_tmp.sum(axis=1).sort_values(ascending=False)
        elif self.partitionScheme == 'vertical':
            # Apply query weights, sum across columns (if more than one)
            qw_proc = self.queryWeights[self.readColInds[0]:self.readColInds[1]]
            # print('Data at proc: ' + str(self.roleNumber) + ' = ' + str(self.data.head()))
            # print('qw at proc: ' + str(self.roleNumber) + ' = ' + str(qw_proc))
            scores_tmp = self.data * qw_proc
            self.scoresOT = scores_tmp.sum(axis=1).astype(int)
            self.scoresOT.index += 1
            self.scores = self.scoresOT.sort_values(ascending=False)
            # row_ids = list(range(1, len(self.scoresOT) + 1))
            # self.scoresOT.set_axis(row_ids, axis='index')
            # self.scores.set_axis(row_ids, axis='index')
            # print('Scores at proc: ' + str(self.roleNumber) + str(self.scores.head(15)))

    def EncryptScores(self, inputValues):
        enc_local_topk  = []
        # Encrypt local top-k values
        # Iterate through received list of entries
        for entry_tmp in inputValues:
            # print('Sending value: ' + str(entry_tmp.value))
            # Inputs: encrypt(self, v, pkey=None, r=None
            r_party         = ElGamal.gen_r(self.ElGamalInfo)
            ID_tmp          = gmpy2.mpz(entry_tmp.ID)

            # ID - encrypt with three layers of ElGamal encryption
            if self.partitionScheme == 'horizontal':
                enc_ele = ID_tmp
                for w in range(self.numberWorkers):
                    ene_ele_r, enc_ele    = ElGamal.encrypt(self.ElGamalInfo, enc_ele, self.ElGamalPubKeys[w].k, r_party)
                # Set ID
                entry_tmp.ID = [ene_ele_r, enc_ele]
            elif self.partitionScheme == 'vertical':
                enc_ele = ID_tmp
                for w in range(self.numberWorkers):
                    ene_ele_r, enc_ele    = ElGamal.encrypt(self.ElGamalInfo, enc_ele, self.ElGamalPubKeys[w][1], r_party)

                # Set ID
                entry_tmp.ID = [ene_ele_r, enc_ele]

            # If horizontal - encrypt the zero & one encodings
            if self.partitionScheme == 'horizontal':
                # Handle zero encoding
                zero_encoding_out = []
                # Iterate through 0/1 encoding lists
                for encode_val in entry_tmp.ZeroEncoding:
                    r_party             = ElGamal.gen_r(self.ElGamalInfo)
                    enc_ele_tmp         = gmpy2.mpz(encode_val)
                    # Inputs: encrypt(self, v, pkey=None, r=None
                    enc_ele_z = enc_ele_tmp
                    for w in range(self.numberWorkers):
                        enc_ele_zr, enc_ele_z    = ElGamal.encrypt(self.ElGamalInfo, enc_ele_z, self.ElGamalPubKeys[w].k, r_party)
                    enc_val_out         = [enc_ele_zr, enc_ele_z]
                    zero_encoding_out.append(enc_val_out)
                entry_tmp.ZeroEncoding  = zero_encoding_out

                # Handle one encoding
                one_encoding_out = []
                # Iterate through 0/1 encoding lists
                for encode_val in entry_tmp.OneEncoding:
                    r_party             = ElGamal.gen_r(self.ElGamalInfo)
                    enc_ele_o         = gmpy2.mpz(encode_val)
                    # Inputs: encrypt(self, v, pkey=None, r=None
                    for w in range(self.numberWorkers):
                        enc_ele_or, enc_ele_o    = ElGamal.encrypt(self.ElGamalInfo, enc_ele_o, self.ElGamalPubKeys[w].k, r_party)
                    enc_val_out         = [enc_ele_or, enc_ele_o]
                    one_encoding_out.append(enc_val_out)
                entry_tmp.OneEncoding   = one_encoding_out

            # If vertical - encrypt with Paillier then three layers of ElGamal encryption
            elif self.partitionScheme == 'vertical':
                    enc_ele_tmp         = gmpy2.mpz(entry_tmp.value)

                    # Encrypt with Paillier
                    r_p             = Paillier.gen_r(self.PaillierHelper, self.PaillierPubKeys[0].pkey)
                    enc_ele_tmp_p   = Paillier.encrypt(self.PaillierHelper, enc_ele_tmp, pkey=self.PaillierPubKeys[0].pkey, r=r_p)
                    enc_ele_tmp_p_inv = gmpy2.invert(enc_ele_tmp_p, gmpy2.mpz(self.PaillierPubKeys[0].pkey.usquare))
                    # Inputs: encrypt(self, v, pkey=None, r=None
                    r_party             = ElGamal.gen_r(self.ElGamalInfo)
                    enc_ele             = enc_ele_tmp_p

                    r_party_inv         = ElGamal.gen_r(self.ElGamalInfo)
                    enc_ele_inv         = enc_ele_tmp_p_inv
                    for w in range(self.numberWorkers):
                        ene_ele_r, enc_ele    = ElGamal.encrypt(self.ElGamalInfo, enc_ele, self.ElGamalPubKeys[w][1], r_party)
                        ene_ele_r_inv, enc_ele_inv    = ElGamal.encrypt(self.ElGamalInfo, enc_ele_inv, self.ElGamalPubKeys[w][1], r_party_inv)
                    enc_val_out         = [ene_ele_r, enc_ele]
                    enc_val_out_inv     = [ene_ele_r_inv, enc_ele_inv]
                    # entry_tmp.encValue  = enc_val_out
                    entry_tmp.encValue = enc_val_out
                    entry_tmp.encValueInvert = enc_val_out_inv

            enc_local_topk.append(entry_tmp)
        return enc_local_topk

    def SortedAccess(self, number_of_IDs):
        access_ID_tmp = range(self.sortedAccessInd, self.sortedAccessInd + number_of_IDs)
        self.sendData = self.data[access_ID_tmp]
        self.sortedAccessInd += 1

    def RandomAccess(self, ID):
        self.sendData = self.data[ID]

    def send_threshold_aggregation(self, count_ind):
        """Send threshold aggregation (TA) information to moderator.
        
        Args:
            count_ind: Current iteration index
            
        Returns:
            tuple: (enc_local_topk, send_val) - encrypted local top-k values and send values
        """
        # Init vars
        if self.security_level == 'secure':
            self.currentIDsum = [1, 1]
        elif self.security_level == 'nonsecure':
            self.currentIDsum = 0

        # Step 1, calculate threshold
        local_send_vals = []
        for ind in range(count_ind, count_ind + 1):
            ranked_ind = self.scores.index[ind]
            send_val = [int(self.scores.index[ind]), int(self.scores.loc[ranked_ind])]
            self.sumID = send_val[0] - 1  # Indices start at 1 for encryption, 0 indexed for accessing...

            # Store entry for mixnet...
            entry_tmp = EntryStorage()
            entry_tmp.ID = send_val[0]
            entry_tmp.noEncID = send_val[0]
            entry_tmp.value = send_val[1]
            local_send_vals.append(entry_tmp)

        if self.security_level == 'secure':
            enc_local_topk = self.EncryptScores(local_send_vals)
        else:
            enc_local_topk = local_send_vals

        # Send encrypted values to moderator through mixnet
        log.debug('Sending TA at proc: ' + str(self.roleNumber))
        destination_role_number = self.roles.index('moderator')
        num_senders = 1 
        self.SendData(self.roleNumber, destination_role_number, 'TA', enc_local_topk, True, num_senders)

        # Connect/key exchange time
        elapsed_time = round(time.time() - self.startTime, 5)
        log.debug(f'Elapsed time start TA round: {elapsed_time}')

        try:
            log.debug('waiting at proc after TA: ' + str(self.roleNumber))
            self.manager.wait1().wait()
        except BrokenBarrierError:
            log.debug('barrier3 err')
            pass

        # PIR/Score summing
        if self.security_level == 'secure':
            self.currentIDsum = enc_local_topk[0].encValue
            self.currentIDsumInvert = enc_local_topk[0].encValueInvert
        else:
            self.currentIDsum = enc_local_topk[0].value

        return enc_local_topk, send_val

    def setup_pir_database(self):
        """Setup PIR database encryption and preprocessing."""
        if self.security_level == 'secure':
            # Distribute Galois keys
            if not len(self.db_enc):
                log.debug('PIR db encrypt start...')
                
                # Change to manager queue (sender puts message in receiver's queue)
                for role_num in range(self.numberParties):
                    if role_num != self.roleNumber:
                        log.debug(f'Sending gk to: {role_num} at proc {self.roleNumber}')
                        get_queue_fxn_tmp = self.q(role_num)
                        get_queue_fxn_tmp().put([self.roleNumber, 'GK', self.galois_keys_bytes])
                        self.calc_data_size([self.roleNumber, 'GK', self.galois_keys_bytes])
                        log.debug(f'sending to queue at memory address {get_queue_fxn_tmp()}')

                get_queue_fxn_tmp = self.q(self.roleNumber)
                log.debug(f'reading from queue at memory address {get_queue_fxn_tmp()}')
                
                for role_num in range(self.numberParties - 1):
                    msg_rcv = get_queue_fxn_tmp().get()
                    gk_ind = msg_rcv[0]
                    gk_keys_bytes = msg_rcv[2]
                    
                    # Write bytes to file for read-in to GaloisKeys constructor
                    newFilePath = './src/tmp_galois_keys/gk' + str(self.roleNumber) + str(gk_ind) + '.bin'
                    newFile = open(newFilePath, "wb")
                    writeInfo = bytearray(gk_keys_bytes)
                    newFile.write(writeInfo)

                    # Create "new" Galois key instance
                    gk = seal.GaloisKeys()
                    gk_context = seal.SEALContext(self.enc_params)
                    gk.load(gk_context, newFilePath)
                    self.pir_server.set_galois_key(gk_ind, gk)

                log.debug('Done receiving GK proc: ' + str(self.roleNumber))

                # Barrier
                try:
                    log.debug('waiting at proc after GK: ' + str(self.roleNumber))
                    self.manager.wait2().wait()
                except BrokenBarrierError:
                    log.debug('barrier4 err')
                    pass

                if self.roleNumber == 0:
                    # Output timing after each round
                    elapsed_time = round(time.time() - self.startTime, 5)
                    log.debug('Elapsed time GK: ' + str(elapsed_time))

            # Setup server database for PIR
            if not len(self.db_enc):
                if self.roleNumber == 0 and picklingFlag:
                    log.debug('Pickling party obj for unit testing...')
                    dump_file_name = './unit_test_party_input'

                    # Remove unpicklable attributes
                    store_attr = ['PaillierPubKeys', 'ElGamalInfo', 'ElGamalPubKeys']
                    dump_dict = {}

                    for attr in store_attr:
                        dump_dict[attr] = self.__dict__[attr]

                # Parallel processing pool...
                self.db_enc_pair = self.pir_encrypt_database()

                if self.roleNumber == 0 and picklingFlag:
                    dump_dict['Expected Output'] = self.db_enc

                    with open(dump_file_name, "wb") as fp:
                        pickle.dump(dump_dict, fp)

                size_per_item = self.e_bit_len * 4 // 8       
                number_of_items = len(self.scoresOT)
                self.pir_server.wrap_database(self.db_enc, number_of_items, size_per_item)
                self.pir_server.preprocess_database()

                # Output timing after each round
                elapsed_time = round(time.time() - self.startTime, 5)
                log.debug('Elapsed time PIR setup: ' + str(elapsed_time))

    def send_pir_queries(self, count_ind):
        """Send PIR queries to other parties.
        
        Args:
            count_ind: Current iteration index
            
        Returns:
            list: Collected PIR queries from other parties
        """
        # Send PQ msg
        # Choose index in db
        self.pir_queries = []
        ele_index = self.sumID
        
        if self.security_level == 'secure':
            index = self.pir_client.get_fv_index(ele_index)             # index of FV plaintext
            self.offset = self.pir_client.get_fv_offset(ele_index)      # offset in FV plaintext

            # Generate query (client)
            query = self.pir_client.generate_query(index)

            # Generate serialized query (client)
            client_string = sealp.StringStreamR()
            output_size = self.pir_client.generate_serialized_query(index, client_string)

        log.debug('Sending PQ at proc: ' + str(self.roleNumber))

        # Use the current round id (count_ind) to tag messages so receivers
        # can filter and ensure replies align to the same round.
        round_id = count_ind

        def _send_pq(p, round_id=round_id):
            """Send a PQ message to party p tagged with round_id.

            We include the round_id as the last element of the payload so
            receivers can ignore messages belonging to other rounds.
            """
            if p == self.roleNumber:
                return None
                
            try:
                if self.security_level == 'secure':
                    # [sender_role, client_string, ele_index, round_id]
                    sendQuery = (self.roleNumber, client_string, ele_index, round_id)
                else:
                    # [sender_role, ele_index, round_id]
                    sendQuery = (self.roleNumber, ele_index, round_id)
                
                queue_proxy = self.qp(p)
                # Use tuple to reduce pickling overhead slightly
                message = (self.roleNumber, 'PQ', sendQuery)
                # Submit non-blocking put to reuse IO executor
                self.io_executor.submit(queue_proxy.put, message)
                
                # Keep accounting for message size
                self.calc_data_size(message)
                return p
            except Exception as e:
                log.debug(f"Failed to send PQ to {p}: {e}")
                return None

        targets = [p for p in range(self.numberParties) if p != self.roleNumber]
        if targets:
            max_workers = min(len(targets), os.cpu_count())
            with ThreadPoolExecutor(max_workers=max_workers) as exe:
                futures = {exe.submit(_send_pq, p): p for p in targets}
                for fut in as_completed(futures):
                    try:
                        _ = fut.result()
                    except Exception as e:
                        log.debug(f"Exception while sending PQ: {e}")

        # Collect only PQ messages that match the current round_id. If
        # we see messages from other rounds, buffer them and re-queue
        # them afterwards to avoid misalignment between rounds.
        expected_pq = self.numberParties - 1
        collected = []
        skipped = []
        queue_proxy = self.qp(self.roleNumber)  # Cached queue proxy
        
        while len(collected) < expected_pq:
            msg_rcv = queue_proxy.get()
            # msg_rcv has form (from_role, 'MSG_ID', payload)
            if len(msg_rcv) < 3:
                # malformed message, skip
                log.debug(f"Malformed PQ msg received at proc {self.roleNumber}: {msg_rcv}")
                continue
            # Ensure we only process PQ here; buffer others
            if msg_rcv[1] != 'PQ':
                skipped.append(msg_rcv)
                continue

            payload = msg_rcv[2]
            # Safely get round tag from payload. If no tag present, treat
            # as matching (backwards compatibility).
            payload_round = payload[-1] if len(payload) > 0 else None

            if payload_round is None or payload_round == round_id:
                # Keep the payload only (original code appended payload)
                collected.append(payload)
            else:
                # Buffer mismatched-round messages and continue receiving
                skipped.append(msg_rcv)

        # Re-queue skipped messages so other rounds/processes can handle them
        if skipped:
            for s in skipped:
                # Use non-blocking put via IO executor
                self.io_executor.submit(queue_proxy.put, s)

        # Assign only collected current-round queries
        self.pir_queries = collected
        
        return collected

    def process_and_reply_queries(self, count_ind):
        """Process received PIR queries and send replies.
        
        Args:
            count_ind: Current iteration index
            
        Returns:
            list: Received PR messages from other parties
        """
        round_id = count_ind
        
        # Process queries and send replies in parallel where safe.
        # - Nonsecure path: lightweight lookups, safe to build+send in threads.
        # - Secure path: seal/sealp calls may be thread-unsafe or CPU-bound; we
        #   generate replies serially then dispatch the queue.put + size accounting
        #   to threads to overlap IO.
        def _send_reply(payload_tuple):
            """Send a prepared reply payload tuple: (dest_role, payload).
            payload already contains round as last element.
            Returns True on success.
            """
            try:
                dest_role, payload = payload_tuple
                queue_proxy = self.qp(dest_role)
                message = (self.roleNumber, 'PR', payload)
                # Non-blocking put using shared IO executor
                self.io_executor.submit(queue_proxy.put, message)
                self.calc_data_size(message)
                return True
            except Exception as e:
                log.debug(f"_send_reply failed for dest {payload_tuple[0]}: {e}")
                return False

        # Prepare a list of payloads to send (dest_role, payload)
        send_payloads = []

        if self.security_level == 'secure':
            # Generate replies serially to avoid calling sealp concurrently.
            for query_tmp in self.pir_queries:
                try:
                    payload_round = query_tmp[-1]
                except Exception:
                    payload_round = round_id

                dest = query_tmp[0]
                if query_tmp[-1] == -1:
                    qid = query_tmp[1]
                    payload = [dest, -1, qid, payload_round]
                else:
                    client_string_tmp = query_tmp[1]
                    query_id = query_tmp[2]
                    server_string = sealp.StringStreamR()
                    query = self.pir_server.deserialize_query(client_string_tmp)
                    reply = self.pir_server.generate_reply(query, dest)
                    self.pir_server.serialize_reply(reply, server_string)
                    payload = [dest, server_string, query_id, payload_round]
                send_payloads.append((dest, payload))
        else:
            # Nonsecure: build payloads lazily and send concurrently
            for query_tmp in self.pir_queries:
                try:
                    payload_round = query_tmp[-1]
                except Exception:
                    payload_round = round_id
                dest = query_tmp[0]
                if query_tmp[-1] == -1:
                    qid = query_tmp[1]
                    payload = [dest, -1, qid, payload_round]
                    send_payloads.append((dest, payload))
                else:
                    query_id = query_tmp[1]
                    # Guard and use iloc by position to avoid index KeyError
                    if query_id < 0 or query_id >= len(self.scoresOT):
                        log.debug(f"Out-of-range query_id {query_id} at proc {self.roleNumber}; skipping")
                        continue
                    # lookup is cheap; do it now (position-based)
                    val_return = self.scoresOT.iloc[query_id]
                    payload = [dest, val_return, query_id, payload_round]
                    send_payloads.append((dest, payload))

        # Dispatch sends in parallel (queue.put + calc_data_size)
        if send_payloads:
            max_workers = min(len(send_payloads), os.cpu_count())
            # Use the existing io_executor to avoid creating pools per round
            futures = [self.io_executor.submit(_send_reply, p) for p in send_payloads]
            for fut in futures:
                try:
                    _ = fut.result()
                except Exception as e:
                    log.debug(f"Exception while sending PR: {e}")

        # Queue replace (collect all PR messages for this round)
        expected_pr = self.numberParties - 1
        received_pr_msgs = []
        skipped_pr = []
        queue_proxy = self.qp(self.roleNumber)  # Cached queue proxy
        
        while len(received_pr_msgs) < expected_pr:
            msg_rcv = queue_proxy.get()
            if len(msg_rcv) < 3:
                log.debug(f"Malformed PR msg received at proc {self.roleNumber}: {msg_rcv}")
                continue
            # Ensure we only process PR here; buffer others
            if msg_rcv[1] != 'PR':
                skipped_pr.append(msg_rcv)
                continue
                
            payload = msg_rcv[2]
            payload_round = payload[-1] if len(payload) > 0 else None
            
            if payload_round is None or payload_round == round_id:
                received_pr_msgs.append(payload)
            else:
                skipped_pr.append(msg_rcv)

        # Re-queue skipped PR messages (belong to other rounds)
        if skipped_pr:
            for s in skipped_pr:
                self.io_executor.submit(queue_proxy.put, s)

        return received_pr_msgs

    def process_query_replies(self, received_pr_msgs, count_ind):
        """Process received query replies and update current ID sum.
        
        Args:
            received_pr_msgs: List of received PR messages
            count_ind: Current iteration index
        """
        if self.security_level == 'secure':
            # Parallel decode and convert to encrypted pairs (c, c_inv)
            def _decode_reply(msg_data):
                reply_deserial = self.pir_client.deserialize_reply(msg_data[1])
                elems = self.pir_client.decode_reply(reply_deserial, self.offset)
                return self.pir_to_encrypted_pair(elems)

            with ThreadPoolExecutor() as executor:
                decoded_pairs = list(executor.map(_decode_reply, received_pr_msgs))

            # Reduce multiply all pairs into currentIDsum and currentIDsumInvert
            sum0, sum1 = self.currentIDsum
            inv0, inv1 = self.currentIDsumInvert
            for c, c_inv in decoded_pairs:
                sum0 = sum0 * c[0]
                sum1 = sum1 * c[1]
                inv0 = inv0 * c_inv[0]
                inv1 = inv1 * c_inv[1]
            self.currentIDsum = [sum0, sum1]
            self.currentIDsumInvert = [inv0, inv1]
        else:
            # Sum plaintext values
            add_sum = sum(msg_data[1] for msg_data in received_pr_msgs)
            self.currentIDsum += add_sum
            # Connect/key exchange time
            elapsed_time = round(time.time() - self.startTime, 5)
            log.debug(f'Elapsed time end retrieval: {elapsed_time}')

    def send_score_generation(self, enc_local_topk, send_val):
        """Send score generation (SG) information to moderator.
        
        Args:
            enc_local_topk: Encrypted local top-k values
            send_val: Send values containing ID and score
            
        Returns:
            tuple: (msg_id, msg_data) - received message ID and data
        """
        # testDuration = time.time()
        # Send SG through mixnet (if ID is new)
        destination_role_number = self.roles.index('moderator')
        num_senders = 1
        local_send_SG = []
        obj_SG_tmp = EntryStorage()
        obj_SG_tmp.noEncID = send_val[0]
        obj_SG_tmp.value = send_val[1]
        obj_SG_tmp.party = self.roleNumber
        if self.security_level == 'secure':
            obj_SG_tmp.ID = enc_local_topk[0].ID

        obj_SG_tmp.encValue = self.currentIDsum
        obj_SG_tmp.encValueInvert = self.currentIDsumInvert
        
        local_send_SG.append(obj_SG_tmp)

        testDuration = time.time()
        
        self.SendData(self.roleNumber, destination_role_number, 'SG', local_send_SG, True, num_senders)

        # Receive TA/QR
        get_queue_fxn_tmp = self.q(self.roleNumber)
        msg_rcv = get_queue_fxn_tmp().get()

        msg_from = msg_rcv[0]
        msg_id = msg_rcv[1]
        msg_data = msg_rcv[2]

        if msg_id == 'TR':
            log.debug('Msg TR, algo continues at proc: ' + str(self.roleNumber))
        elif msg_id == 'QR':
            self.topKreturn = msg_data
            self.checkTA = False

        # Connect/key exchange time
        # elapsed_time = round(time.time() - self.startTime, 5)
        elapsed_time = time.time()
        # log.debug(f'Elapsed time end TA round: {elapsed_time}')
        log.debug(f'Duration time end SG round: {round(elapsed_time - testDuration, 5)}')

        return msg_id, msg_data

    def ProcessLoop(self):#barrier, barrier2, barrier3, barrier4, event):
        # self.initFlag   = True
        # print('Pickling party obj for unit testing...')
        # dump_file_name  = './pir_encrypt_database_input'
        # dump_obj        = self
        # with open(dump_file_name, "wb") as fp:
        #     pickle.dump(dump_obj, fp)
        #     fp.close()
        # print('Pickling dump complete...')
        # Initialize socket connection - barrier to wait for all procs to setup socket
        self.connect_to_manager()
        self.SetupSocket()#barrier)

        # Receive public encryption keys from workers
        if self.security_level == 'secure':
            if self.partitionScheme == 'horizontal':
                self.connection_count = 0
                self.exp_connects = (self.numberWorkers + 1)    # 3 ElGamal keys, 1 ElGamal Gp info
            elif self.partitionScheme == 'vertical': 
                self.exp_connects = 2 #(self.numberWorkers + 2)    # 3 ElGamal keys, 1 ElGamal Gp info, 1 Paillier key
            # print('Receiving keys at party: ' + str(self.roleNumber))
            # self.RcvData()
            # print('Done receiving keys at party: ' + str(self.roleNumber))

            # Queue replace (rcv)
            for rcv_count in range(self.numberWorkers + 2):
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

        # Wait for all parties/workers to get to this point
        try:
            log.debug('Waiting at key barrier proc: ' + str(self.roleNumber))
            self.manager.wait0().wait()#barrier2.wait()
            log.debug('Key barrier broken at proc: ' + str(self.roleNumber))
        except BrokenBarrierError:
            pass

        # If query originator, send query weights to all other parties
        if self.role == 'query_originator':
            num_senders = 1
            for i in range(self.numberParticipants):
                if i != self.roleNumber:
                    # self.SendData(self.roleNumber, i, 'QW', [self.queryWeights, self.k], False, num_senders)
                    query_msg = [self.queryWeights, self.k]
                    get_queue_fxn_tmp = self.q(i)
                    get_queue_fxn_tmp().put([self.roleNumber, 'QW', query_msg])
                    self.calc_data_size(query_msg)

        # If party, receive query weights
        elif self.role == 'party':
            get_queue_fxn_tmp = self.q(self.roleNumber)
            msg_rcv = get_queue_fxn_tmp().get()

            msg_from = msg_rcv[0]
            msg_id = msg_rcv[1]
            msg_data = msg_rcv[2]

            if msg_id == 'QW':
                self.queryWeights   = msg_data[0]
                self.k              = msg_data[1]
                log.debug('k = ' + str(self.k))

        # Calculate scores
        self.CalculateScores()

        # Wait for all parties/workers to get to this point
        try:
            log.debug('Waiting at QW proc: ' + str(self.roleNumber))
            self.manager.wait0().wait()#barrier2.wait()
        except BrokenBarrierError:
            pass

        if self.partitionScheme == 'horizontal':
            # Send top-k scores to moderator
            local_topk      = []
            local_topk_tmp  = self.scores[:self.k].tolist()
            for ind in range(0, self.k):
                local_topk.append([int(self.scores.index[ind]), [int(local_topk_tmp[ind])]])
            local_topk_encoding = []
            expected_bit_len = 20
            for val in local_topk:
                entry_tmp = EntryStorage()
                zeroSet = Encoding.calcZeroEncoding(self, val[1][0], expected_bit_len)
                oneSet  = Encoding.calcOneEncoding(self, val[1][0], expected_bit_len)
                entry_tmp.ID = val[0]
                entry_tmp.noEncID = val[0]
                entry_tmp.value   = val[1][0]
                entry_tmp.ZeroEncoding = zeroSet
                entry_tmp.OneEncoding  = oneSet
                local_topk_encoding.append(entry_tmp)
            enc_local_topk  = self.EncryptScores(local_topk_encoding)
            # Send encrypted values to moderator through mixnet
            destination_role_number = self.roles.index('moderator')
            num_senders = 1
            self.SendData(self.roleNumber, destination_role_number, 'KV', enc_local_topk, True, num_senders)

            # Wait to receive query output
            self.connection_count, self.exp_connects = 0, 1
            self.RcvData()


        elif self.partitionScheme == 'vertical':
            if self.roleNumber == 0:
                # Output timing after each round
                elapsed_time = round(time.time() - self.startTime, 5)
                log.debug('Elapsed time at entry point: ' + str(elapsed_time))

            # Initialize PIR parameters
            if self.security_level == 'secure':
                self.gen_p = Paillier.gen_r(self.PaillierHelper, self.PaillierPubKeys[0].pkey)
                self.gen_e = ElGamal.gen_r(self.ElGamalInfo)
                self.pir_init()

            # while loop steps 1 - 4
            count_ind = 0
            while True:
                # Step 1: Send threshold aggregation (TA) information
                enc_local_topk, send_val = self.send_threshold_aggregation(count_ind)
                
                # Step 2: Setup PIR database (only on first iteration)
                self.setup_pir_database()

                # Step 3: Send PIR queries and collect responses
                self.send_pir_queries(count_ind)
                
                # Step 4: Process queries and send replies, then receive replies
                received_pr_msgs = self.process_and_reply_queries(count_ind)
                
                # Step 5: Process received replies and update current ID sum
                self.process_query_replies(received_pr_msgs, count_ind)

                # Step 6: Send score generation (SG) and receive response
                msg_id, msg_data = self.send_score_generation(enc_local_topk, send_val)

                count_ind += 1

                if not self.checkTA:
                    break

        query_answer = []
        for id_ret in self.topKreturn:
            query_answer.append(int(id_ret))

        log.debug('Query return = ' + str(query_answer) + ' at proc: ' + str(self.roleNumber))

        if self.roleNumber == 1 and self.security_level == 'secure':
            log.debug('Expected: ' + str(self.expected_answer) + ', Received: ' + str(query_answer))
            assert(query_answer == self.expected_answer)
            log.debug('Correct answer returned...')

        log.debug('Party ' + str(self.roleNumber) + ', finished process loop!')
        log.debug('Proc ' + str(self.roleNumber) + ' sent ' + str(self.CommunicationMB) + ' total bytes of data')

        if self.partitionScheme == 'horizontal':
            # Tell workers (2 & 3) communication has concluded
            num_senders = 1
            for w in range(self.numberWorkers - 1):
                self.SendData(self.roleNumber, (self.numberParties + w + 1), 'XX', [], False, num_senders)
        elif self.partitionScheme == 'vertical':
            # Tell workers (2 & 3) communication has concluded
            num_senders = 1
            for w in range(self.numberWorkers - 1):
                self.SendData(self.roleNumber, (self.numberParties + w + 1), 'XX', [], False, num_senders)
        
        # Clean up resources
        self.cleanup()
        log.debug('Proc ' + str(self.roleNumber) + ' has terminated')



def setupParty(unitTest=False):
    # Start time
    start_time = time.time()

    try:
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
        log.debug('Party set using inputs...')
    except:
        log.debug('Using default inputs...')
        dataset          = 'raisin'
        norm_type        = 'l1'
        query_weights_in = '1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1'
        k_in             = '4'
        num_parties      = 3
        num_workers      = 3
        partition_scheme = 'vertical'
        security_level   = 'secure'
        role_number      = 1
        address_list     = ['localhost'] * (num_parties + num_workers)

    # # Parse query weights
    log.debug(f'party: DATASET={dataset},NORM_TYPE={norm_type},QW={query_weights_in},k={k_in},num_p={num_parties},num_w={num_workers},role_num={role_number},adds={address_list}')
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

    # Initialize communication envrionment
    CE   = CommunicationEnvironment(allAddresses, num_parties, num_workers, roles)

    # Specify data location and partitions
    # data_prepath = '/mnt/efs/fs1/FedTopK_Dev_working/data/processed'
    data_prepath = './data/processed'
    print(f"dataset = {dataset}")
    if norm_type == 'l1':
        if dataset == 'raisin':
            file_path = f'{data_prepath}/l1_raisin.csv'
        elif dataset == 'housing':
            file_path = f'{data_prepath}/l1_housing.csv'
        elif dataset == 'dry_bean':
            file_path = f'{data_prepath}/l1_drybean.csv'
        elif dataset == 'wine_quality':
            file_path = f'{data_prepath}/l1_winequality.csv'
        elif dataset == 'shuttle':
            file_path = f'{data_prepath}/l1_shuttle.csv'
    elif norm_type == 'l2':
        if dataset == 'raisin':
            file_path = f'{data_prepath}/l2_raisin.csv'
        elif dataset == 'housing':
            file_path = f'{data_prepath}/l2_housing.csv'
        elif dataset == 'dry_bean':
            file_path = f'{data_prepath}/l2_drybean.csv'
        elif dataset == 'wine_quality':
            file_path = f'{data_prepath}/l2_winequality.csv'
        elif dataset == 'shuttle':
            file_path = f'{data_prepath}/l2_shuttle.csv'
    else:
        raise ValueError(f'Invalid norm_type: {norm_type}')
    print(f"file_path = {file_path}")

    # Check output top-k IDs
    cols            = list(pd.read_csv(file_path, nrows = 1))
    data_series_tmp = pd.read_csv(file_path)
    data_series_tmp.index += 1
    num_cols = len(data_series_tmp.columns)
    # Default query weights are equal (i.e. all ones)
    QueryWeights = np.ones(num_cols)
    print(f'QW check: {query_weights_in}')
    if query_weights_in == 'exponential':
        # print('Enter qw')
        exp_weights = []
        for col_tmp in range(num_cols):
            weight_tmp = (2 ** col_tmp)
            exp_weights.append(1 / weight_tmp) # Change to 1 for normal use (1000 used for wine L2 exponential)
            # print(f"exp_weights = {exp_weights}")
        QueryWeights = QueryWeights * np.array(exp_weights)
    print(f"QueryWeights = {QueryWeights}")
    scores_tmp      = data_series_tmp * QueryWeights
    db_len          = len(scores_tmp)

    expected_scores = scores_tmp.sum(axis=1).sort_values(ascending=False)[:k]
    expected_ids    = list(expected_scores.index)
    expected_ids.reverse()      # Sync order with algo return
    log.debug(expected_scores)
    # print(expected_ids)

    # Initialize parties (Inputs: Role number, role, partition scheme, communication environment)
    if role_number == 1:
        partyRole = Party(role_numbers[role_number], roles[role_number], partition_scheme, security_level, CE, norm_type, QueryWeights, k, startTime = start_time, expected_answer=expected_ids)
    else:
        partyRole = Party(role_numbers[role_number], roles[role_number], partition_scheme, security_level, CE, norm_type, startTime = start_time)
    
    if security_level == 'secure':
        partyRole.set_pir_params(db_len, e_bit_len)
    partyRole.ReadDataVertical(file_path)        

    # Create multiprocessing
    if not unitTest:
        # Execute protocol
        partyRole.ProcessLoop()
    else:
        return partyRole

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

    setupParty()
