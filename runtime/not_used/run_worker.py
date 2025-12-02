import numpy as np
import gmpy2
import time
import sys
import multiprocessing as mp

# FedTopK imports
sys.path.append("./src")
from communication_helper import CommunicationEnvironment
from threading import BrokenBarrierError, Lock
from security.elgamal import ElGamal
from security.paillier import Paillier
from mixnet_helper import Mixnet
from manager import get_ServerManager


# Enter main execution
rand = gmpy2.random_state(hash(gmpy2.random_state()))

class elgamal_send():
    def __init__(self):
        self.g = None
        self.p = None

class paillier_send():
    def __init__(self):
        self.pkey       = None
        self.u          = None
        self.s          = None
        self.usquare    = None

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
        self.aggregateTopK      = []
        self.aggregateTopKuni   = np.array([])
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
        self.barrier2           = None
        self.checkID_barrier    = False
        self.checkTA_barrier    = False
        self.countIDs           = 0

        # Security keys
        self.ElGamalInfo        = ElGamalInfo
        self.ElGamalPubKeys     = []  # x & k
        self.PaillierInfo       = PaillierInfo
        self.PaillierPubKeys    = []  # u & s

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
        self.ID_store           = []
        self.TA                 = None

    def connect_to_manager(self):
        # print('Manager address: ' + str(self.addresses[-1]))
        self.manager = get_ServerManager(self.addresses[-1], self.numberParties, self.numberWorkers, self.role)
        
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
        
    def DistributeKeys(self):
        # Distribute ElGamal public keys
        self.connection_count = 0
        # Receive public encryption keys from other workers
        if self.partitionScheme == 'horizontal':
            self.exp_connects = (self.roleNumber - self.numberParties)
            if self.roleNumber > self.numberParties:
                self.RcvData()          # 2 ElGamal keys

        elif self.partitionScheme == 'vertical':
            self.exp_connects = (self.roleNumber - self.numberParties)
            if self.roleNumber > self.numberParties:
                self.RcvData() 

        if self.partitionScheme == 'horizontal':
            num_senders = 1
        elif self.partitionScheme == 'vertical':
            num_senders = 1

        for role_num in range(self.numberParticipants):
            if role_num != self.roleNumber:
                if self.partitionScheme == 'horizontal':
                    self.SendData(self.roleNumber, role_num, 'EK', self.ElGamalInfo.get_ekey(), False, num_senders)
                elif self.partitionScheme == 'vertical':
                    key_tmp     = self.ElGamalInfo.get_ekey()
                    key_send    = [self.roleNumber, key_tmp.k]
                    self.SendData(self.roleNumber, role_num, 'EK', key_send, False, num_senders)

                # Last worker messages
                # Distribute Paillier public keys
                if self.roleNumber == (self.numberParticipants - 1):
                    if self.partitionScheme == 'vertical':
                        PaillierSend = paillier_send()
                        PaillierSend.pkey = self.PaillierInfo.get_pkey()
                        self.SendData(self.roleNumber, role_num, 'PK', PaillierSend, False, num_senders)

                    # Distribute EG.p & EG.g to all parties
                    if role_num < self.numberParties:
                        ElGamal_send = elgamal_send()
                        ElGamal_send.g, ElGamal_send.p = self.ElGamalInfo.g, self.ElGamalInfo.p
                        self.SendData(self.roleNumber, role_num, 'GP', ElGamal_send, False, num_senders)

        # Receive keys etc
        self.connection_count = 0
        self.exp_connects = (self.numberParticipants - self.roleNumber - 1)
        if self.roleNumber < (self.numberParticipants - 1):
            self.RcvData()

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
        print('Number of compares: ' + str(count))
        return data

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
                r_p                 = Paillier.gen_r(self.PaillierSend)
                enc_ele_tmp_p       = Paillier.encrypt(self.PaillierSend, self.randNumInit, r=r_p)
            else:
                r_p                 = Paillier.gen_r(self.PaillierPubKeys[0])
                enc_ele_tmp_p       = Paillier.encrypt(self.PaillierPubKeys[0], self.randNumInit, r=r_p)

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
            num_senders = 2
            self.connection_count = 0
            self.exp_connects = (self.roleNumber - self.numberParties)
            if self.roleNumber > self.numberParties:
                print('RG rcv at proc: ' + str(self.roleNumber) + ', expected connections: ' + str(self.exp_connects))
                self.RcvData()
                print('RG rcv broke at proc: ' + str(self.roleNumber))

            for role_num in range(self.numberParties, self.numberParticipants):
                if role_num != self.roleNumber:
                    print('Sending random number to proc: ' + str(role_num) + ', from ' + str(self.roleNumber))
                    self.SendData(self.roleNumber, role_num, 'RG', self.randNumInit, False, num_senders)

            # Receive keys etc
            self.connection_count = 0
            self.exp_connects = (self.numberParticipants - self.roleNumber - 1)
            if self.roleNumber < (self.numberParticipants - 1):
                self.RcvData()

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
                r_p                 = Paillier.gen_r(self.PaillierSend)
                enc_ele_tmp_p       = Paillier.encrypt(self.PaillierSend, self.randNum_tmp, r=r_p)
            else:
                r_p                 = Paillier.gen_r(self.PaillierPubKeys[0])
                enc_ele_tmp_p       = Paillier.encrypt(self.PaillierPubKeys[0], self.randNum_tmp, r=r_p)

            # Encrypt with own EG key
            s_1             = gmpy2.mpz_random(rand, self.ElGamalInfo.p) + 1
            gr_s1, m_s1     = ElGamal.encrypt(self.ElGamalInfo, enc_ele_tmp_p, self.ElGamalInfo.k, s_1)

            # Encrypt with other workers keys (if applicable)
            for EGPubKey in self.ElGamalPubKeys:
                if EGPubKey[0] > self.roleNumber:
                    _, m_s1     = ElGamal.encrypt(self.ElGamalInfo, m_s1, EGPubKey[1], s_1)

            # Set sum_val
            sum_val_tmp = [1, 1]
            sum_val_tmp[0], sum_val_tmp[1]      = self.sum_val[0] * gr_s1, self.sum_val[1] * m_s1
            self.sum_val[0], self.sum_val[1]    = gmpy2.f_mod(sum_val_tmp[0], self.ElGamalInfo.p), gmpy2.f_mod(sum_val_tmp[1], self.ElGamalInfo.p)

            # Unencrypted check
            self.sum_val_noEnc  += self.randNum_tmp

            # Set send sum val (difference)
            # Encrypt with Paillier
            if self.roleNumber == (self.numberParticipants - 1):
                # print('Proc: ' + str(self.roleNumber) + ' encrypting with P1 key')
                r_p2                 = Paillier.gen_r(self.PaillierSend)
                enc_ele_tmp_p2       = Paillier.encrypt(self.PaillierSend, send_CRS_unEnc, r=r_p2)
            else:
                # print('Proc: ' + str(self.roleNumber) + ' encrypting with P2 key')
                r_p2                 = Paillier.gen_r(self.PaillierPubKeys[0])
                enc_ele_tmp_p2       = Paillier.encrypt(self.PaillierPubKeys[0], send_CRS_unEnc, r=r_p2)

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
            num_senders = 1

            if self.roleNumber == (self.numberParticipants - 1):
                destination_role_number = self.roles.index('moderator')
                self.SendData(self.roleNumber, destination_role_number, 'RS', self.sum_send_val, False, num_senders)
            else:
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
            print('Waiting at setup barrier proc: ' + str(self.roleNumber))
            self.manager.wait0().wait()#barrier2.wait()
        except BrokenBarrierError:
            pass

        # Receive query weights
        self.connection_count, self.exp_connects = 0, 1
        self.RcvData()
        print('Query weights rcv at proc: ' + str(self.roleNumber))

        if self.partitionScheme == 'horizontal':
            self.batchSize = self.k * self.numberParties    # Batch size equals k * m (all returned values)
            # Wait for all parties/workers to get to this point
            try:
                print('Waiting at entry barrier, proc: ' + str(self.roleNumber))
                self.manager.wait0().wait()#barrier2.wait()
                print('Entry barrier broken, proc: ' + str(self.roleNumber))
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
                print('Waiting at post QW barrier, proc: ' + str(self.roleNumber))
                self.manager.wait0().wait()#barrier2.wait()
                print('QW barrier broken at proc: ' + str(self.roleNumber))
            except BrokenBarrierError:
                pass

            # Initialize consistent random sum
            if self.security_level == 'secure':
                # Generate random number
                self.genDistRandNum()

                # Wait for all parties/workers to get to this point
                try:
                    print('Waiting at post-GenDistRandNum proc: ' + str(self.roleNumber))
                    self.manager.wait0().wait()#barrier2.wait()
                except BrokenBarrierError:
                    pass

            print('Workers entered algo at proc: ' + str(self.roleNumber))

            # Moderator process loop
            if self.role == 'moderator':
                # self.manager = manager
                # self.barrier2 = barrier2
                # self.barrier3 = barrier3
                self.batchSize = self.numberParties
                while True:
                    self.RcvStatus = True
                    while self.RcvStatus and self.checkTA:
                        self.connection_count, self.exp_connects = 0, 1
                        self.RcvData()

                    # Step 4, check scores against threshold
                    kCount = 0
                    unique_tmp, unique_inds = np.unique(self.aggregateTopKuni, return_index=True)
                    comp_vals = [self.aggregateTopK[index] for index in unique_inds]
                    print('comp_vals')
                    for entry_tmp in comp_vals: #self.aggregateTopK[unique_inds]:
                        # print('compare to k vals')
                        print(entry_tmp.noEncID, entry_tmp.encValue - self.Gamma, self.TA - self.Gamma)
                        if entry_tmp.encValue > self.TA: # - self.Gamma:
                            kCount += 1

                    # Distribute query return or repeat algorithm
                    num_senders = 1
                    # print('kCount: ' + str(kCount) + ' , k: ' + str(self.k))
                    if kCount < self.k:
                        num_senders = 1
                        for p in range(self.numberParties):
                            self.SendData(self.roleNumber, p, 'TR', [], False, num_senders)
                            self.checkTA = True
                        self.numRounds += 1
                    else:
                        # self.aggregateTopK.sort(reverse=True)
                        query_return_IDs    = []
                        query_return_scores = []

                        for entry in comp_vals: #self.aggregateTopK:
                            if self.security_level == 'secure':
                                query_return_IDs.append(entry.ID)
                            elif self.security_level == 'nonsecure':
                                query_return_IDs.append(entry.noEncID)
                            query_return_scores.append(entry.encValue)
                        sort_inds = np.argsort(query_return_scores)
                        qr_IDs = np.asarray(query_return_IDs)[sort_inds]
                        qr_scores = np.asarray(query_return_scores)[sort_inds]
                        query_return = list(qr_IDs[-self.k:])
                        num_senders = 1
                        if self.security_level == 'secure':
                            mix_query_return = self.DecryptionMixnet(query_return)
                        elif self.security_level == 'nonsecure':
                            mix_query_return = query_return
                        self.SendData(self.roleNumber, 0, 'QR', mix_query_return, True, num_senders) # Will send to all parties...
                        break
                    print('Moderator begining next round...')
            else:
                self.RcvStatus = True
                while self.RcvStatus:
                    self.connection_count, self.exp_connects = 0, 1
                    self.RcvData()
                print('Rcv broke at proc: ' + str(self.roleNumber))

        # Print end time
        if self.role == 'moderator':
            print("--- %s seconds ---" % (time.time() - self.startTime))
            print('Number of TA rounds required: ' + str(self.numRounds))
        else:
            print('Worker: ' + str(self.roleNumber) + ', finished process loop!')

        print('Proc ' + str(self.roleNumber) + ' sent ' + str(self.CommunicationMB) + ' total bytes of data')
        print('Proc ' + str(self.roleNumber) + ' has terminated')

        if self.roleNumber == (self.numberParticipants - 1):
            self.manager.set().set()


def setupWorker(unitTest=False):
    # Start time
    start_time = time.time()

    # try:
    # Handle inputs (add partitioning scheme and security level...)
    dataset          = sys.argv[1]
    query_weights_in = sys.argv[2]
    k_in             = sys.argv[3]
    num_parties      = int(sys.argv[4])
    num_workers      = int(sys.argv[5])
    partition_scheme = sys.argv[6]
    security_level   = sys.argv[7]
    role_number      = int(sys.argv[8])
    print('Worker set using inputs...')
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

    if security_level == 'secure':
        # Generate EG info for each worker
        eg_worker_info = []
        for w in range(num_workers):
            eg_worker_info.append(ElGamal(e_key_len, e_bit_len))

        if partition_scheme == 'vertical':
            # Add check on Paillier group length
            p_bit_len   = int(np.sqrt(e_bit_len))
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
                print('key gen count: ' + str(count))
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
    setupWorker()
