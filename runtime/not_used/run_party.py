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

# FedTopK Imports
sys.path.append("./src")
from security.elgamal import ElGamal
from security.paillier import Paillier
from bit_compare import Encoding
from time import sleep
from sealpir import SealPIR, PirParams
import seal
import sealp
from manager import get_ServerManager


# Enter main execution
picklingFlag = False

def binary_to_uint8(party_obj, bytestring, db_enc):
    # top_ten             = party_obj.scores[:15].index
    expected_byte_len   = len(bytestring) - 2
    # print(expected_byte_len)
    byte_tmp            = []
    for byte in range(expected_byte_len):
        db_enc.append(bytestring[byte + 2])
        byte_tmp.append(bytestring[byte + 2])

    while expected_byte_len < 256:
        # If byte length 255 (add 0 in front)
        db_enc.append(0)
        byte_tmp.append(0)
        expected_byte_len = len(byte_tmp)

    py_bytes = list(bytestring[2:])
    if len(py_bytes) < 256:
        py_bytes.append(0)

    return db_enc

class EntryStorage():
    def __init__(self):
        self.ID             = None
        self.noEncID        = None
        self.value          = None
        self.encValue       = None
        self.ZeroEncoding   = None
        self.OneEncoding    = None
        self.party          = None
        self.sum            = None
        self.newID          = None

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
    def __init__(self, role_number, role, partition_scheme, security_level, CommEnv, query_weights=None, k_param=None, startTime=None, expected_answer=None):
        super().__init__(CommEnv.addresses, CommEnv.numberParties, CommEnv.numberWorkers, CommEnv.roles)#, CommEnv.lock)
        self.socket             = None
        self.moderatorInd       = 1
        self.roleNumber         = role_number
        self.role               = role
        self.partitionScheme    = partition_scheme
        self.expected_answer    = expected_answer
        self.security_level     = security_level
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

        # Multiprocessing
        if self.roleNumber == (self.numberParties - 1):
            self.num_process    = 2 # If None, defaults to os.cpu_count(), change to (os.cpu_count() - 1)?
        else:
            self.num_process    = 1
        # self.process_pool       = mp.Pool(processes=self.num_process, maxtasksperchild=2)

        # Not used
        self.sendData           = None
        self.sortedAccessInd    = 0

    # def __getstate__(self):
    #     d = dict(self.__dict__)
    #     if self.initFlag:
    #         remove_list = ['lock', 'socket', 'pir_client', 'pir_server', 'galois_keys']
    #         print('getstate1')
    #         for attr in remove_list:
    #             del d[attr]
    #     else:
    #         print('getstate0')

    #     return d

    # def __setstate__(self, state):
    #     print('setstate')
    #     self.__dict__.update(state)

    def connect_to_manager(self):
        self.manager = get_ServerManager(self.addresses[-1], self.numberParties, self.numberWorkers, self.role)
        # print('Manager address: ' + str(self.addresses[-1]))
        # self.manager = get_ServerManager(self.addresses[-1], self.numberParties, self.numberWorkers, self.role)
        
        count = 0
        while True:
            try:
                print('Trying to connect to mananger, proc: ' + str(self.roleNumber))
                self.manager.connect()#barrier.wait()
                print('Connected to manger, proc: ' + str(self.roleNumber))
                break
            except Exception as e:
                print('Manager connection error:')
                print(e)
                time.sleep(2.5)
                if count > 25:
                    break
            count += 1

    def set_pir_params(self, db_len, e_bit_len):
        self.db_len     = db_len
        self.e_bit_len  = e_bit_len

    def pir_init(self):
        # Generate PIR parameters
        self.enc_params, self.pir_params = SealPIR.gen_pir_params(self.db_len, self.e_bit_len)

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
        gk_file_name = 'gk' + str(self.roleNumber) + '.bin'
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
            r_p             = 6 # self.gen_p # Paillier.gen_r(self.PaillierPubKeys[0])
            enc_ele_tmp_p   = Paillier.encrypt(self.PaillierPubKeys[0], enc_ele_tmp, r=r_p)

            # Inputs: encrypt(self, v, pkey=None, r=None
            r_party             = 6 # self.gen_e # ElGamal.gen_r(self.ElGamalInfo)
            enc_ele = enc_ele_tmp_p
            for w in range(self.numberWorkers):
                ene_ele_r, enc_ele    = ElGamal.encrypt(self.ElGamalInfo, enc_ele, self.ElGamalPubKeys[w][1], r_party)
            enc_val_out         = [ene_ele_r, enc_ele]
            db_enc_pair.append(enc_val_out)

            # Save encrypted pair to encrypted db
            bin_tmp_01 = gmpy2.to_binary(enc_val_out[0])
            bin_tmp_02 = gmpy2.to_binary(enc_val_out[1])
            db_enc = binary_to_uint8(self, bin_tmp_01, db_enc)
            db_enc = binary_to_uint8(self, bin_tmp_02, db_enc)
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
        
        byte_tmp01 = byte_tmp[:256]
        byte_tmp02 = byte_tmp[256:]

        if byte_tmp01[-1] == 0:
            byte_tmp01 = byte_tmp01[:-1]
        if byte_tmp02[-1] == 0:
            byte_tmp02 = byte_tmp02[:-1]

        byte_tmp01[0:0] = b_tmp
        byte_tmp02[0:0] = b_tmp

        c0 = gmpy2.from_binary(bytes(byte_tmp01))
        c1 = gmpy2.from_binary(bytes(byte_tmp02))
        return c0, c1

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
        cols_use        = [i for i in cols if i != 'Class']
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
            print('ID_tmp = ' + str(ID_tmp))

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
                    r_p             = Paillier.gen_r(self.PaillierPubKeys[0])
                    enc_ele_tmp_p   = Paillier.encrypt(self.PaillierPubKeys[0], enc_ele_tmp, r=r_p)

                    # Inputs: encrypt(self, v, pkey=None, r=None
                    r_party             = ElGamal.gen_r(self.ElGamalInfo)
                    enc_ele             = enc_ele_tmp_p
                    for w in range(self.numberWorkers):
                        ene_ele_r, enc_ele    = ElGamal.encrypt(self.ElGamalInfo, enc_ele, self.ElGamalPubKeys[w][1], r_party)
                    enc_val_out         = [ene_ele_r, enc_ele]
                    entry_tmp.encValue  = enc_val_out

            enc_local_topk.append(entry_tmp)
        return enc_local_topk

    def SortedAccess(self, number_of_IDs):
        access_ID_tmp = range(self.sortedAccessInd, self.sortedAccessInd + number_of_IDs)
        self.sendData = self.data[access_ID_tmp]
        self.sortedAccessInd += 1

    def RandomAccess(self, ID):
        self.sendData = self.data[ID]

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
                self.exp_connects = (self.numberWorkers + 2)    # 3 ElGamal keys, 1 ElGamal Gp info, 1 Paillier key
            self.RcvData()
            # print('Done receiving keys at party: ' + str(self.roleNumber))

        # Wait for all parties/workers to get to this point
        try:
            print('Waiting at key barrier proc: ' + str(self.roleNumber))
            self.manager.wait0().wait()#barrier2.wait()
            print('Key barrier broken at proc: ' + str(self.roleNumber))
        except BrokenBarrierError:
            pass

        # If query originator, send query weights to all other parties
        if self.role == 'query_originator':
            num_senders = 1
            for i in range(self.numberParticipants):
                if i != self.roleNumber:
                    self.SendData(self.roleNumber, i, 'QW', [self.queryWeights, self.k], False, num_senders)
        # If party, receive query weights
        elif self.role == 'party':
            self.connection_count, self.exp_connects = 0, 1
            self.RcvData()                  

        # Calculate scores
        self.CalculateScores()

        # Wait for all parties/workers to get to this point
        try:
            print('Waiting at QW proc: ' + str(self.roleNumber))
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
                print('Elapsed time at entry point: ' + str(elapsed_time))

            # Initialize PIR parameters
            if self.security_level == 'secure':
                self.gen_p = Paillier.gen_r(self.PaillierPubKeys[0])
                self.gen_e = ElGamal.gen_r(self.ElGamalInfo)
                self.pir_init()

            # while loop steps 1 - 4
            count_ind = 0
            while True:
                # Init vars
                if self.security_level == 'secure':
                    self.currentIDsum = [1, 1]
                elif self.security_level == 'nonsecure':
                    self.currentIDsum = 0

                # Step 1, calculate threshold
                local_send_vals = []
                for ind in range(count_ind, count_ind + 1):
                    ranked_ind = self.scores.index[ind]
                    # print('ind = ' + str(ind))
                    # print('scores ind = ' + str(self.scores.index[ind]))
                    send_val = [int(self.scores.index[ind]), int(self.scores.loc[ranked_ind])]
                    self.sumID = send_val[0] - 1 # Incides start at 1 for encryption, 0 indexed for accessing...

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

                # Wait for all parties/workers to get to this point
                if not self.randNumInit_flag and self.security_level == 'secure':
                    try:
                        print('Waiting at post-GenDistRandNum proc: ' + str(self.roleNumber))
                        self.manager.wait0().wait()#barrier2.wait()
                    except BrokenBarrierError:
                        pass
                    self.randNumInit_flag = True

                # Send encrypted values to moderator through mixnet
                print('Sending TA at proc: ' + str(self.roleNumber))
                destination_role_number = self.roles.index('moderator')
                num_senders = 1 
                self.SendData(self.roleNumber, destination_role_number, 'TA', enc_local_topk, True, num_senders)

                # Barrier after TA
                try:
                    print('waiting at proc after TA: ' + str(self.roleNumber))
                    self.manager.wait1().wait()#barrier3.wait()
                except BrokenBarrierError:
                    print('barrier3 err')
                    pass

                # Step 2, check ID(s)
                # Send ID for checks
                ID_check_msg = EntryStorage()
                ID_check_msg.ID = enc_local_topk[0].ID
                ID_check_msg.noEncID = self.sumID
                ID_check_msg.party = self.roleNumber
                destination_role_number = self.roleNumber
                num_senders = 1
                # print('Sending ID = ' + str(self.sumID) + ' at proc: ' + str(self.roleNumber))
                self.SendData(self.roleNumber, destination_role_number, 'ID', ID_check_msg, True, num_senders)

                # Init receive
                self.connection_count, self.exp_connects = 0, 1
                self.RcvData()
                print('Rcvd IS = ' + str(self.newIdFlag) + ', for ID = ' + str(self.sumID) + ' at proc: ' + str(self.roleNumber))

                # Barrier after ID
                try:
                    print('waiting at proc after IS: ' + str(self.roleNumber))
                    self.manager.wait1().wait()#barrier3.wait()
                except BrokenBarrierError:
                    print('barrier3 err')
                    pass

                if self.roleNumber == 0:
                        # Output timing after each round
                        elapsed_time = round(time.time() - self.startTime, 5)
                        print('Elapsed time ID: ' + str(elapsed_time))

                # PIR/Score summing
                if self.security_level == 'secure':
                    self.currentIDsum = enc_local_topk[0].encValue
                else:
                    self.currentIDsum = enc_local_topk[0].value

                # Distribute Galois keys
                if self.security_level == 'secure':
                    if not len(self.db_enc):
                        print('Encrypting entire dataset for PIR...')
                        # if self.roleNumber == 0 and picklingFlag:
                        #     with open(dump_file_name, "wb") as fp:
                        #         pickle.dump(dump_obj, fp)
                        #         fp.close()
                        #     print('Pickling dump complete...')

                            # Load obj
                            # input_file_name = './pir_encrypt_database_input'
                            # print('Loading pickle file...')
                            # with open(dump_file_name, 'rb') as f:
                            #     party_instance = pickle.load(f)
                            # print('Pickled obj loaded...')
                        self.connection_count = 0
                        self.exp_connects = self.roleNumber
                        if self.roleNumber > 0:
                            self.RcvData()        
                        num_senders = 1

                        for p in range(self.numberParties):
                            if p != self.roleNumber:
                                sendGK = [self.roleNumber, self.galois_keys_bytes]
                                self.SendData(self.roleNumber, p, 'GK', sendGK, False, num_senders)

                        # Send/rcv GK keys
                        self.connection_count = 0
                        self.exp_connects = (self.numberParties - self.roleNumber - 1)
                        if self.roleNumber < (self.numberParties - 1):
                            self.RcvData()
                        # print('Done receiving GK proc: ' + str(self.roleNumber))

                        # Barrier
                        try:
                            print('waiting at proc after GK: ' + str(self.roleNumber))
                            self.manager.wait2().wait()#barrier4.wait()
                        except BrokenBarrierError:
                            print('barrier4 err')
                            pass

                        if self.roleNumber == 0:
                            # Output timing after each round
                            elapsed_time = round(time.time() - self.startTime, 5)
                            print('Elapsed time GK: ' + str(elapsed_time))

                    # Setup server database for PIR
                    if not len(self.db_enc):
                        print('Encrypting entire dataset for PIR...')
                        if self.roleNumber == 0 and picklingFlag:
                            print('Pickling party obj for unit testing...')
                            dump_file_name  = './unit_test_party_input'

                            # Remove unpicklable attributes
                            store_attr  = ['PaillierPubKeys', 'ElGamalInfo', 'ElGamalPubKeys']
                            dump_dict   = {}

                            for attr in store_attr:
                                dump_dict[attr] = self.__dict__[attr]

                        # Parallel processing pool...
                        self.db_enc_pair = self.pir_encrypt_database()

                        if self.roleNumber == 0 and picklingFlag:
                            dump_dict['Expected Output'] = self.db_enc

                            with open(dump_file_name, "wb") as fp:
                                pickle.dump(dump_dict, fp)

                        size_per_item    = self.e_bit_len * 2 // 8          # 2048 * 2 // 8 (8 = storing as uint8)
                        number_of_items  = len(self.scoresOT)
                        # elapsed_time = round(time.time() - self.startTime, 5)
                        # print('Dataset encrypted...' + str(elapsed_time))
                        self.pir_server.wrap_database(self.db_enc, number_of_items, size_per_item)
                        self.pir_server.preprocess_database()
                        # elapsed_time = round(time.time() - self.startTime, 5)
                        # print('Dataset wrapped and preprocessed...' + str(elapsed_time))
                        if self.roleNumber == 0:
                            # Output timing after each round
                            elapsed_time = round(time.time() - self.startTime, 5)
                            print('Elapsed time PIR setup: ' + str(elapsed_time))

                # Send PQ msg
                # Choose index in db
                self.pir_queries = []
                ele_index   = ID_check_msg.noEncID
                # print('Printing unencrypted ID: ' + str(ele_index) + ', at proc: ' + str(self.roleNumber))
                if self.security_level == 'secure':
                    index = self.pir_client.get_fv_index(ele_index)             # index of FV plaintext
                    self.offset = self.pir_client.get_fv_offset(ele_index)      # offset in FV plaintext

                    # Generate query (client)
                    query = self.pir_client.generate_query(index)

                    # Generate serialized query (client)
                    client_string = sealp.StringStreamR()
                    output_size = self.pir_client.generate_serialized_query(index, client_string)

                # Distribute client queries
                self.connection_count = 0
                self.exp_connects = self.roleNumber
                if self.roleNumber > 0:
                    self.RcvData()        
                num_senders = 1

                for p in range(self.numberParties):
                    if p != self.roleNumber:
                        # Send client queries
                        if self.security_level == 'secure':
                            sendQuery = [self.roleNumber, client_string, ele_index]
                        elif self.security_level == 'nonsecure':
                            sendQuery = [self.roleNumber, ele_index]
                        self.SendData(self.roleNumber, p, 'PQ', sendQuery, False, num_senders)

                # Receive queries etc
                self.connection_count = 0
                self.exp_connects = (self.numberParties - self.roleNumber - 1)
                if self.roleNumber < (self.numberParties - 1):
                    self.RcvData()
                # print('Done receiving PQ proc: ' + str(self.roleNumber))

                # Barrier
                try:
                    print('waiting at proc after PQ: ' + str(self.roleNumber))
                    self.manager.wait2().wait()#barrier4.wait()
                except BrokenBarrierError:
                    print('barrier4 err')
                    pass

                # Process queries
                self.pir_send_replies = []

                for query_tmp in self.pir_queries:
                    send_role_num       = query_tmp[0]
                    if self.security_level == 'secure':
                        client_string_tmp   = query_tmp[1]
                        query_id            = query_tmp[2]
                        server_string       = sealp.StringStreamR()
                        query = self.pir_server.deserialize_query(client_string_tmp)

                        # Query processing (server)
                        reply = self.pir_server.generate_reply(query, send_role_num)

                        # Serialize reply (server)
                        reply_size = self.pir_server.serialize_reply(reply, server_string)
                        sendReply = [send_role_num, server_string, query_id]
                    elif self.security_level == 'nonsecure':
                        query_id   = query_tmp[1]
                        print('query_id: ' + str(query_id) + 'at proc: ' + str(self.roleNumber))
                        val_return = self.scoresOT[query_id+1]
                        sendReply = [send_role_num, val_return, query_id]
                    self.pir_send_replies.append(sendReply)

                # Send replies (PR)
                # Distribute server replies
                self.connection_count = 0
                self.exp_connects = self.roleNumber
                if self.roleNumber > 0:
                    self.RcvData()        
                num_senders = 1


                for reply in self.pir_send_replies:
                    # Send client queries
                    sendReply2 = [self.roleNumber, reply[1], reply[2]]
                    # pir_start_ind   = reply[2] * size_per_item
                    # pir_end_ind     = (reply[2] + 1) * size_per_item
                    self.SendData(self.roleNumber, reply[0], 'PR', sendReply2, False, num_senders)

                # Receive PR
                self.connection_count = 0
                self.exp_connects = (self.numberParties - self.roleNumber - 1)
                if self.roleNumber < (self.numberParties - 1):
                    self.RcvData()
                # print('Done receiving PR proc: ' + str(self.roleNumber))

                # Barrier
                try:
                    print('waiting at proc after PR: ' + str(self.roleNumber))
                    self.manager.wait2().wait()#barrier4.wait()
                except BrokenBarrierError:
                    print('barrier4 err')
                    pass

                if self.roleNumber == 0:
                    # Output timing after each round
                    elapsed_time = round(time.time() - self.startTime, 5)
                    print('Elapsed time PIR: ' + str(elapsed_time))

                # Send SG through mixnet (if ID is new)
                destination_role_number = self.roles.index('moderator')
                num_senders         = 1
                local_send_SG       = []
                obj_SG_tmp          = EntryStorage()
                obj_SG_tmp.noEncID  = send_val[0]
                obj_SG_tmp.value    = send_val[1]
                obj_SG_tmp.party    = self.roleNumber
                if self.security_level == 'secure':
                    obj_SG_tmp.ID   = enc_local_topk[0].ID

                if not self.newIdFlag:
                    obj_SG_tmp.value    = 0
                    obj_SG_tmp.encValue = 0
                else:
                    obj_SG_tmp.encValue = self.currentIDsum
                
                local_send_SG.append(obj_SG_tmp)
                print('Sending ID: ' + str(obj_SG_tmp.noEncID) + ' with score: ' + str(obj_SG_tmp.encValue))
                self.SendData(self.roleNumber, destination_role_number, 'SG', local_send_SG, True, num_senders)

                # Receive TA/QR
                self.connection_count, self.exp_connects = 0, 1
                self.RcvData()

                # Barrier
                try:
                    print('waiting at proc after TR_QR: ' + str(self.roleNumber))
                    self.manager.wait2().wait()#barrier4.wait()
                except BrokenBarrierError:
                    print('barrier4 err')
                    pass

                count_ind += 1

                if not self.checkTA:
                    break

        query_answer = []
        for id_ret in self.topKreturn:
            query_answer.append(int(id_ret))

        print('Query return = ' + str(query_answer) + ' at proc: ' + str(self.roleNumber))

        if self.roleNumber == 1:
            print('Expected: ' + str(self.expected_answer) + ', Received: ' + str(query_answer))
            assert(query_answer == self.expected_answer)
            print('Correct answer returned...')

        print('Party ' + str(self.roleNumber) + ', finished process loop!')
        print('Proc ' + str(self.roleNumber) + ' sent ' + str(self.CommunicationMB) + ' total bytes of data')

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
        print('Proc ' + str(self.roleNumber) + ' has terminated')



def setupParty(unitTest=False):
    # Start time
    start_time = time.time()

    try:
        # Handle inputs (add partitioning scheme and security level...)
        dataset          = sys.argv[1]
        query_weights_in = sys.argv[2]
        k_in             = sys.argv[3]
        num_parties      = int(sys.argv[4])
        num_workers      = int(sys.argv[5])
        partition_scheme = sys.argv[6]
        security_level   = sys.argv[7]
        role_number      = int(sys.argv[8])
        print('Party set using inputs...')
    except:
        print('Using default inputs...')
        dataset          = 'wine_quality'
        query_weights_in = '1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1'
        k_in             = '4'
        num_parties      = 3
        num_workers      = 3
        partition_scheme = 'vertical'
        security_level   = 'secure'
        role_number      = 1

    # Check for and remove added comma
    # if ',' in k_in:
    #     k_in = k_in[:-1]

    # Parse query weights
    query_weights = []

    for i in query_weights_in.split(', '):
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

    # Initialize query
    QueryWeights    = np.array(query_weights)
    k               = int(k_in)

    # Define security environment
    e_key_len   = 224                         # NIST recommended: 224  (160 for compare to SECYAN)
    e_bit_len   = 2048                        # NIST recommended: 2048 (1024 for compare to SECYAN)

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
    cols            = list(pd.read_csv(file_path, nrows = 1))
    data_series_tmp = pd.read_csv(file_path)
    data_series_tmp.index += 1
    scores_tmp      = data_series_tmp * QueryWeights
    db_len          = len(scores_tmp)

    expected_scores = scores_tmp.sum(axis=1).sort_values(ascending=False)[:k]
    expected_ids    = list(expected_scores.index)
    print(expected_scores)
    print(expected_ids)

    # Initialize parties (Inputs: Role number, role, partition scheme, communication environment)
    if role_number == 1:
        partyRole = Party(role_numbers[role_number], roles[role_number], partition_scheme, security_level, CE, QueryWeights, k, startTime = start_time)
    else:
        partyRole = Party(role_numbers[role_number], roles[role_number], partition_scheme, security_level, CE, startTime = start_time)
    
    if security_level == 'secure':
        partyRole.set_pir_params(db_len, e_bit_len)
    partyRole.ReadDataVertical(file_path)        

    # Create multiprocessing
    if not unitTest:
        # barrier     = mp.Barrier(num_participants + 1) # All participants + main thread....
        # barrier2    = mp.Barrier(num_participants)     # All participants
        # barrier3    = mp.Barrier(num_participants - (num_workers - 1)) # All parties and one mixnet worker (moderator)
        # barrier4    = mp.Barrier(num_parties)
        # event       = mp.Event()

        # Execute protocol
        partyRole.ProcessLoop()#barrier, barrier2, barrier3, barrier4, event)
    else:
        return partyRole

if __name__ == '__main__':
    setupParty()


