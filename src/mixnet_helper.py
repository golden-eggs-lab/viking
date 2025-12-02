import numpy as np
import gmpy2
from messages import EntryStorage
from security.elgamal import ElGamal
from security.paillier import Paillier
import random
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
import multiprocessing

# Remove self as input to fxns (& __init__)?
log = logging.getLogger('fedtopk')

# Initialize state
rand = gmpy2.random_state(hash(gmpy2.random_state()))

class Mixnet():
    def __init__(self):
        pass

    # Horizontal step 1
    def RefreshMixnet(self, workerClass, msg_data):
        output_message_tmp      = []
        # Iterate k times
        for entry_tmp in msg_data:            
            # Re-randomize message (changes g^r...)
            s_1             = gmpy2.mpz_random(rand, workerClass.ElGamalInfo.p) + 1
            ID_tmp          = entry_tmp.ID

            # Use public keys and private key to encrypt value of 1
            m_s1 = 1
            for w in range(workerClass.numberWorkers - 1):
                _, m_s1     = ElGamal.encrypt(workerClass.ElGamalInfo, m_s1, workerClass.ElGamalPubKeys[w].k, s_1)
            gr_s1, m_s1     = ElGamal.encrypt(workerClass.ElGamalInfo, m_s1, workerClass.ElGamalInfo.k, s_1)
            grm3, m_4       = ID_tmp[0] * gr_s1, ID_tmp[1] * m_s1
            grm3, m_4       = gmpy2.f_mod(grm3, workerClass.ElGamalInfo.p), gmpy2.f_mod(m_4, workerClass.ElGamalInfo.p)
            rand_msg        = [grm3, m_4]
            # Store ID
            entry_tmp.ID = rand_msg

            # Handle zero encoding
            zero_encoding_out = []
            # Iterate through 0/1 encoding lists
            for encode_val in entry_tmp.ZeroEncoding:
                # Re-randomize message (changes g^r...)
                s_1             = gmpy2.mpz_random(rand, workerClass.ElGamalInfo.p) + 1
                enc_ele_tmp     = encode_val
                # Use public keys and private key to encrypt value of 1
                m_s1 = 1
                for w in range(workerClass.numberWorkers - 1):
                    _, m_s1     = ElGamal.encrypt(workerClass.ElGamalInfo, m_s1, workerClass.ElGamalPubKeys[w].k, s_1)
                gr_s1, m_s1     = ElGamal.encrypt(workerClass.ElGamalInfo, m_s1, workerClass.ElGamalInfo.k, s_1)
                grm3, m_4       = enc_ele_tmp[0] * gr_s1, enc_ele_tmp[1] * m_s1
                grm3, m_4       = gmpy2.f_mod(grm3, workerClass.ElGamalInfo.p), gmpy2.f_mod(m_4, workerClass.ElGamalInfo.p)
                rand_msg        = [grm3, m_4]
                # Store ID
                zero_encoding_out.append(rand_msg)
            entry_tmp.ZeroEncoding = zero_encoding_out

            # Handle one encoding
            one_encoding_out = []
            # Iterate through 0/1 encoding lists
            for encode_val in entry_tmp.OneEncoding:
                # Re-randomize message (changes g^r...)
                s_1             = gmpy2.mpz_random(rand, workerClass.ElGamalInfo.p) + 1
                enc_ele_tmp     = encode_val
                # Use public keys and private key to encrypt value of 1
                m_s1 = 1
                for w in range(workerClass.numberWorkers - 1):
                    _, m_s1     = ElGamal.encrypt(workerClass.ElGamalInfo, m_s1, workerClass.ElGamalPubKeys[w].k, s_1)
                gr_s1, m_s1     = ElGamal.encrypt(workerClass.ElGamalInfo, m_s1, workerClass.ElGamalInfo.k, s_1)
                grm3, m_4       = enc_ele_tmp[0] * gr_s1, enc_ele_tmp[1] * m_s1
                grm3, m_4       = gmpy2.f_mod(grm3, workerClass.ElGamalInfo.p), gmpy2.f_mod(m_4, workerClass.ElGamalInfo.p)
                rand_msg        = [grm3, m_4]
                # Store ID
                one_encoding_out.append(rand_msg)
            entry_tmp.OneEncoding = one_encoding_out

            output_message_tmp.append(entry_tmp)

        # Permute output messages
        perm_inds = list(range(len(msg_data)))
        random.shuffle(perm_inds)                   # Shuffle in-place
        output_message = [output_message_tmp[i] for i in perm_inds]
        return(output_message)

    # Horizontal step 2
    def MultiplicativeMixnet(self, workerClass, msg_data):
        output_message  = []
        # Iterate through ID & value
        reEncryptFlag   = True
        sk_2            = gmpy2.mpz_random(rand, workerClass.ElGamalInfo.p) + 1
        # Iterate through input encodings: [[oneEncoding], [zeroEncoding]]
        for encoding in msg_data:
            encoding_out = []
            for msg_in in encoding:
                # Decrypt message
                msg_tmp = ElGamal.decrypt(workerClass.ElGamalInfo, msg_in[0], msg_in[1])
                # Re-encrypt message
                if reEncryptFlag:
                    gr_rec, m_rec   = gmpy2.powmod(msg_in[0], sk_2, workerClass.ElGamalInfo.p), gmpy2.powmod(msg_tmp, sk_2, workerClass.ElGamalInfo.p)
                    reenc_message   = [gr_rec, m_rec]
                else:
                    reenc_message   = [msg_in[0], msg_tmp]
                encoding_out.append(reenc_message)
            output_message.append(encoding_out)
        return(output_message)

    # Horizontal step 3
    def DecryptionMixnet(self, workerClass, msg_data):
        output_message_tmp      = []
        # Iterate through ID & value
        val_out_tmp = []
        # Iterate through values
        for msg_in in msg_data:
            # Decrypt message
            msg_tmp = workerClass.ElGamalInfo.decrypt(msg_in[0], msg_in[1])
            deenc_msg = [msg_in[0], msg_tmp]
            val_out_tmp.append(deenc_msg)
        output_message = val_out_tmp
        return(output_message)

    # Vertical step 1 - Can remove any ID sending/processing
    def AdditiveMixnetTA(self, workerClass, msg_data):
        output_message_tmp  = [] # Will be a list of IDs and summed threshold
        summedScore         = [1, 1]
        testSum = 0
    #     new_entry = EntryStorage()
    #     # print('message in: ' + str(msg_data))
    #     # print('sum_val in mixnet = ' + str(workerClass.sum_val) + ' at proc: ' + str(workerClass.roleNumber))
        # If first worker
        # if workerClass.roleNumber == workerClass.numberParties:
        for entry_tmp in msg_data:
            # Calculate sum
            summedScore[0], summedScore[1] = summedScore[0] * entry_tmp.encValue[0], summedScore[1] * entry_tmp.encValue[1]
            summedScore[0], summedScore[1] = gmpy2.f_mod(summedScore[0], workerClass.ElGamalInfo.p), gmpy2.f_mod(summedScore[1], workerClass.ElGamalInfo.p)
            testSum += entry_tmp.value
        # Set TA object
        new_entry = EntryStorage()
        new_entry.ID = 'TA'
        new_entry.value = testSum

        new_entry.encValue = summedScore
        output_message_tmp.append(new_entry)
        return(output_message_tmp)

    #         # Add sum value
    #         # summedScore[0], summedScore[1] = summedScore[0] * workerClass.sum_val[0], summedScore[1] * workerClass.sum_val[1]
    #         # summedScore[0], summedScore[1] = gmpy2.f_mod(summedScore[0], workerClass.ElGamalInfo.p), gmpy2.f_mod(summedScore[1], workerClass.ElGamalInfo.p)

    #         # Decrypt ElGamal
    #         # summedScoreDec = ElGamal.decrypt(workerClass.ElGamalInfo, summedScore[0], summedScore[1])

    #         # Re-randomize
    #         # Gen random number
    #         s_2             = gmpy2.mpz_random(rand, workerClass.ElGamalInfo.p) + 1
    #         # Use public keys and private key to encrypt value of 1
    #         rer_val = 1
    #         # Encrypt with ElGamal public key of all workers further in mixnet
    #         for EGPubKey in workerClass.ElGamalPubKeys:
    #             # print('EGPubKey Encrypt at proc: ' + str(workerClass.roleNumber))
    #             gr_s1, rer_val     = ElGamal.encrypt(workerClass.ElGamalInfo, rer_val, EGPubKey[1], s_2)
    #         gr_s1, rer_val  = ElGamal.encrypt(workerClass.ElGamalInfo, rer_val, workerClass.ElGamalInfo.k, s_2)
    #         grm3, m_4       = entry_tmp.encValue[0] * gr_s1, entry_tmp.encValue[1] * rer_val
    #         grm3, m_4       = gmpy2.f_mod(grm3, workerClass.ElGamalInfo.p), gmpy2.f_mod(m_4, workerClass.ElGamalInfo.p)
    #         sum_msg         = [grm3, m_4]

    #         # Store and append
    #         new_entry.encValue = sum_msg
    #         output_message_tmp.append(new_entry)

    #     # Permute output messages
    #     perm_inds = list(range(len(output_message_tmp)))
    #     random.shuffle(perm_inds)                   # Shuffle in-place
    #     output_message = [output_message_tmp[i] for i in perm_inds]

    #     return(output_message)

    # Vertical step 3
    def AdditiveMixnet(self, workerClass, msg_data):
        output_message_tmp  = []
        # print('message in: ' + str(msg_data))

        for entry_tmp in msg_data:
            new_entry = EntryStorage()

            # Store ID & value
            new_entry.value     = entry_tmp.value
            new_entry.noEncID   = entry_tmp.noEncID
            

            # If last worker decrypt with Paillier
            if workerClass.roleNumber == (workerClass.numberParticipants - 1):
                # sum_msg, _ = Paillier.decrypt(workerClass.PaillierInfo, msg_dec)
                # For last worker, keep the original encValue
                new_entry.encValue = entry_tmp.encValue
                new_entry.encValueInvert = entry_tmp.encValueInvert

            # If first or middle worker, re-randomize value
            else:
                # Re-randomize
                # Gen random number
                s_2             = gmpy2.mpz_random(rand, workerClass.ElGamalInfo.p) + 1
                # Use public keys and private key to encrypt value of 1
                rer_val = 1
                # Encrypt with ElGamal public key of all workers further in mixnet
                for EGPubKey in workerClass.ElGamalPubKeys:
                    # print('EGPubKey Encrypt at proc: ' + str(workerClass.roleNumber))
                    gr_s1, rer_val     = ElGamal.encrypt(workerClass.ElGamalInfo, rer_val, EGPubKey[1], s_2)
                gr_s1, rer_val  = ElGamal.encrypt(workerClass.ElGamalInfo, rer_val, workerClass.ElGamalInfo.k, s_2)
                grm3, m_4       = entry_tmp.encValue[0] * gr_s1, entry_tmp.encValue[1] * rer_val
                grm3_inv, m_4_inv       = entry_tmp.encValueInvert[0] * gr_s1, entry_tmp.encValueInvert[1] * rer_val
                grm3, m_4       = gmpy2.f_mod(grm3, workerClass.ElGamalInfo.p), gmpy2.f_mod(m_4, workerClass.ElGamalInfo.p)
                grm3_inv, m_4_inv       = gmpy2.f_mod(grm3_inv, workerClass.ElGamalInfo.p), gmpy2.f_mod(m_4_inv, workerClass.ElGamalInfo.p)
                sum_msg = [grm3, m_4]
                sum_msg_inv = [grm3_inv, m_4_inv]
                # sum_msg = [entry_tmp.encValue[0], msg_dec]

                # Set new encrypted value (after decryption, re-randomization)
                new_entry.encValue = sum_msg
                new_entry.encValueInvert = sum_msg_inv

            # Re-randomize ID
            # Gen random number
            s_2             = gmpy2.mpz_random(rand, workerClass.ElGamalInfo.p) + 1
            # Use public keys and private key to encrypt value of 1
            rer_val         = 1
            # Encrypt with ElGamal public key of other workers
            for EGPubKey in workerClass.ElGamalPubKeys:
                # print('EGPubKey Encrypt at proc: ' + str(workerClass.roleNumber))
                gr_s1, rer_val     = ElGamal.encrypt(workerClass.ElGamalInfo, rer_val, EGPubKey[1], s_2)
            gr_s1, rer_val  = ElGamal.encrypt(workerClass.ElGamalInfo, rer_val, workerClass.ElGamalInfo.k, s_2)
            grm3, m_4       = entry_tmp.ID[0] * gr_s1, entry_tmp.ID[1] * rer_val
            grm3, m_4       = gmpy2.f_mod(grm3, workerClass.ElGamalInfo.p), gmpy2.f_mod(m_4, workerClass.ElGamalInfo.p)
            encID           = [grm3, m_4]

            # Set ID
            # Decrypt value with ElGamal
            # msg_dec = ElGamal.decrypt(workerClass.ElGamalInfo, entry_tmp.ID[0], entry_tmp.ID[1])
            new_entry.ID    = encID #[entry_tmp.ID[0], entry_tmp.ID[1]] #encID #entry_tmp.ID

            # Store and append
            output_message_tmp.append(new_entry)

        # Permute output messages
        perm_inds = list(range(len(output_message_tmp)))
        random.shuffle(perm_inds)                   # Shuffle in-place
        output_message = [output_message_tmp[i] for i in perm_inds]

        return(output_message)

    # Vertical step 2
    def ComparativeMixnetID(self, workerClass, msg_data):
        output_message = []
        # Initialize re-encryption value for the round...
        p = workerClass.ElGamalInfo.p
        sk_2           = 2 #gmpy2.mpz_random(rand, p) + 1

        # Iterate through inputs
        ##### Compare to other input messages as well as existing list? #####
        assert len(msg_data) == 1, "msg_data should have only one element"
        msg_tmp = msg_data[0]

        # print(msg_tmp)
        # First worker
        if workerClass.roleNumber == workerClass.numberParties:
            # Calculate inverse of input msg
            enc_ID = msg_tmp.ID
            # print(enc_ID)
            gr_inv, m_inv   = gmpy2.invert(enc_ID[0], workerClass.ElGamalInfo.p), gmpy2.invert(enc_ID[1], workerClass.ElGamalInfo.p)

            # Iterate through stored ID list
            # assert len(workerClass.ID_store.heap) != 0, "heap is not empty"

            if hasattr(workerClass.ID_store, 'sorted_list') and len(workerClass.ID_store.sorted_list):

                # Parallelize processing of stored IDs using futures
                def _cmp_id_first_worker_task(ele_tmp):
                    new_entry = EntryStorage()
                    enc_stored_ID = ele_tmp.ID
                    gr_str, m_str = enc_stored_ID[0], enc_stored_ID[1]

                    # Mult/mod
                    grT_tmp, mT_tmp = gmpy2.mul(gr_inv, gr_str), gmpy2.mul(m_inv, m_str)
                    grT, mT         = gmpy2.f_mod(grT_tmp, workerClass.ElGamalInfo.p), gmpy2.f_mod(mT_tmp, workerClass.ElGamalInfo.p)

                    # Decrypt ElGamal
                    msgID_dec = ElGamal.decrypt(workerClass.ElGamalInfo, grT, mT)
                    new_entry.noEncID = msg_tmp.noEncID
                    new_entry.party = msg_tmp.party

                    # Re-encrypt
                    gr_rec, m_rec   = gmpy2.powmod(grT, sk_2, workerClass.ElGamalInfo.p), gmpy2.powmod(msgID_dec, sk_2, workerClass.ElGamalInfo.p)

                    # Re-randomize with a thread-local random state
                    local_rand      = gmpy2.random_state(hash((threading.get_ident(), gmpy2.random_state())))
                    s_2             = gmpy2.mpz_random(local_rand, workerClass.ElGamalInfo.p) + 1
                    rer_val         = 1
                    for EGPubKey in workerClass.ElGamalPubKeys:
                        if EGPubKey[0] > workerClass.roleNumber:
                            gr_s1, rer_val = ElGamal.encrypt(workerClass.ElGamalInfo, rer_val, EGPubKey[1], s_2)
                    grm3, m_4       = gr_rec * gr_s1, m_rec * rer_val
                    grm3, m_4       = gmpy2.f_mod(grm3, workerClass.ElGamalInfo.p), gmpy2.f_mod(m_4, workerClass.ElGamalInfo.p)
                    new_entry.equalityCheck    = [grm3, m_4]
                    new_entry.ID               = enc_ID
                    new_entry.encValue         = msg_tmp.encValue
                    new_entry.encValueInvert   = msg_tmp.encValueInvert
                    new_entry.value            = msg_tmp.value
                    return new_entry

                with ThreadPoolExecutor() as executor:
                    compareID = list(executor.map(_cmp_id_first_worker_task, workerClass.ID_store.sorted_list))
                output_message.append(compareID)
            else:
                new_entry = EntryStorage()
                new_entry.newID = True
                new_entry.party = msg_tmp.party
                new_entry.noEncID = msg_tmp.noEncID
                new_entry.ID = enc_ID
                new_entry.encValue = msg_tmp.encValue
                new_entry.encValueInvert = msg_tmp.encValueInvert
                output_message.append(new_entry)

        # Middle worker(s) decrypt, re-encrypt, re-randomize
        elif workerClass.roleNumber > workerClass.numberParties and workerClass.roleNumber < (workerClass.numberParticipants - 1):
            if isinstance(msg_tmp, list):
                # Parallelize processing of message entries using futures
                def _cmp_id_middle_worker_task(ele_tmp):
                    new_entry = EntryStorage()
                    msgID_dec = ElGamal.decrypt(workerClass.ElGamalInfo, ele_tmp.equalityCheck[0], ele_tmp.equalityCheck[1])
                    new_entry.party = ele_tmp.party
                    new_entry.noEncID = ele_tmp.noEncID

                    # Re-encrypt
                    gr_rec, m_rec   = gmpy2.powmod(ele_tmp.equalityCheck[0], sk_2, workerClass.ElGamalInfo.p), gmpy2.powmod(msgID_dec, sk_2, workerClass.ElGamalInfo.p)

                    # Re-randomize with a thread-local random state
                    local_rand      = gmpy2.random_state(hash((threading.get_ident(), gmpy2.random_state())))
                    s_2             = gmpy2.mpz_random(local_rand, workerClass.ElGamalInfo.p) + 1
                    rer_val         = 1
                    for EGPubKey in workerClass.ElGamalPubKeys:
                        if EGPubKey[0] > workerClass.roleNumber:
                            gr_s1, rer_val     = ElGamal.encrypt(workerClass.ElGamalInfo, rer_val, EGPubKey[1], s_2)
                    grm3, m_4       = gr_rec * gr_s1, m_rec * rer_val
                    grm3, m_4       = gmpy2.f_mod(grm3, workerClass.ElGamalInfo.p), gmpy2.f_mod(m_4, workerClass.ElGamalInfo.p)
                    new_entry.equalityCheck    = [grm3, m_4]
                    new_entry.ID               = ele_tmp.ID
                    new_entry.encValue         = ele_tmp.encValue
                    new_entry.encValueInvert   = ele_tmp.encValueInvert
                    new_entry.value            = ele_tmp.value
                    return new_entry

                with ThreadPoolExecutor() as executor:
                    compareID = list(executor.map(_cmp_id_middle_worker_task, msg_tmp))

                output_message.append(compareID)
            else:
                new_entry = EntryStorage()
                new_entry.newID = True
                new_entry.party = msg_tmp.party
                new_entry.noEncID = msg_tmp.noEncID
                new_entry.ID = msg_tmp.ID
                new_entry.encValue = msg_tmp.encValue
                new_entry.encValueInvert = msg_tmp.encValueInvert
                output_message.append(new_entry)

        # Last worker
        elif workerClass.roleNumber == (workerClass.numberParticipants - 1):
            if isinstance(msg_tmp, list):
                # Parallelize evaluation then reduce to first matching entry in original order
                from functools import reduce
                def _last_worker_task(args):
                    idx, ele_tmp = args
                    new_entry = EntryStorage()
                    msgID_dec = ElGamal.decrypt(workerClass.ElGamalInfo, ele_tmp.equalityCheck[0], ele_tmp.equalityCheck[1])
                    new_entry.party = ele_tmp.party
                    new_entry.noEncID = ele_tmp.noEncID
                    new_entry.ID = ele_tmp.ID
                    new_entry.encValue = ele_tmp.encValue
                    new_entry.encValueInvert   = ele_tmp.encValueInvert
                    new_entry.value            = ele_tmp.value
                    m_rec   = gmpy2.powmod(msgID_dec, sk_2, workerClass.ElGamalInfo.p)
                    is_match = (m_rec == 1)
                    new_entry.newID = not is_match
                    return (idx, new_entry, is_match)

                with ThreadPoolExecutor() as executor:
                    results = list(executor.map(_last_worker_task, enumerate(msg_tmp)))

                # Ensure results are in input order
                results.sort(key=lambda x: x[0])

                # Reduce to the first matching entry; if none, pick the last entry produced (preserves original semantics)
                def _pick_compare(acc, cur):
                    found, chosen = acc
                    _, entry, is_match = cur
                    if found:
                        return (found, chosen)
                    if is_match:
                        return (True, entry)
                    return (False, entry)  # keep updating to the most recent non-match

                _, compareID = reduce(_pick_compare, results, (False, None))

                # Append output message
                output_message.append(compareID)
            else:
                new_entry = EntryStorage()
                new_entry.newID = True
                new_entry.party = msg_tmp.party
                new_entry.noEncID = msg_tmp.noEncID
                new_entry.ID = msg_tmp.ID
                new_entry.encValue = msg_tmp.encValue
                new_entry.encValueInvert = msg_tmp.encValueInvert
                output_message.append(new_entry)

        return output_message

    def ComparativeMixnet(self, workerClass, msg_data):
        output_message = []
        # Initialize re-encryption value for the round...
        sk_2           = 2 #gmpy2.mpz_random(rand, workerClass.ElGamalInfo.p) + 1

        # Iterate through inputs
        ##### Compare to other input messages as well as existing list? #####
        for msg_tmp in msg_data:
            # print(msg_tmp)
            # First worker
            if workerClass.roleNumber == workerClass.numberParties:
                # Calculate inverse of input msg
                enc_ID = msg_tmp.ID
                # print(enc_ID)
                gr_inv, m_inv   = gmpy2.invert(enc_ID[0], workerClass.ElGamalInfo.p), gmpy2.invert(enc_ID[1], workerClass.ElGamalInfo.p)

                # Iterate through stored ID list
                if hasattr(workerClass.ID_store, 'sorted_list') and len(workerClass.ID_store.sorted_list):
                    compareID = []
                    for ele_tmp in workerClass.ID_store.sorted_list:
                        new_entry = EntryStorage()
                        enc_stored_ID = ele_tmp.ID
                        gr_str, m_str = enc_stored_ID[0], enc_stored_ID[1]

                        # Mult/mod
                        grT_tmp, mT_tmp = gmpy2.mul(gr_inv, gr_str), gmpy2.mul(m_inv, m_str)
                        grT, mT         = gmpy2.f_mod(grT_tmp, workerClass.ElGamalInfo.p), gmpy2.f_mod(mT_tmp, workerClass.ElGamalInfo.p)

                        # Decrypt ElGamal
                        msgID_dec = ElGamal.decrypt(workerClass.ElGamalInfo, grT, mT)
                        new_entry.noEncID = msg_tmp.noEncID
                        new_entry.party = msg_tmp.party

                        # Re-encrypt
                        gr_rec, m_rec   = gmpy2.powmod(grT, sk_2, workerClass.ElGamalInfo.p), gmpy2.powmod(msgID_dec, sk_2, workerClass.ElGamalInfo.p)

                        # Re-randomize
                        # Gen random number
                        s_2             = gmpy2.mpz_random(rand, workerClass.ElGamalInfo.p) + 1
                        # Use public keys and private key to encrypt value of 1
                        rer_val         = 1
                        # Encrypt with ElGamal public key of all workers further in mixnet
                        for EGPubKey in workerClass.ElGamalPubKeys:
                            if EGPubKey[0] > workerClass.roleNumber:
                                gr_s1, rer_val     = ElGamal.encrypt(workerClass.ElGamalInfo, rer_val, EGPubKey[1], s_2)
                        grm3, m_4       = gr_rec * gr_s1, m_rec * rer_val
                        grm3, m_4       = gmpy2.f_mod(grm3, workerClass.ElGamalInfo.p), gmpy2.f_mod(m_4, workerClass.ElGamalInfo.p)
                        new_entry.ID    = [grm3, m_4]
                        compareID.append(new_entry)

                    output_message.append(compareID)
                else:
                    new_entry = EntryStorage()
                    new_entry.newID = True
                    new_entry.party = msg_tmp.party
                    new_entry.noEncID = msg_tmp.noEncID
                    output_message.append(new_entry)

            # Middle worker(s) decrypt, re-encrypt, re-randomize
            elif workerClass.roleNumber > workerClass.numberParties and workerClass.roleNumber < (workerClass.numberParticipants - 1):
                if isinstance(msg_tmp, list):
                    compareID = []
                    for ele_tmp in msg_tmp:
                        new_entry = EntryStorage()
                        # Decrypt ElGamal
                        msgID_dec = ElGamal.decrypt(workerClass.ElGamalInfo, ele_tmp.ID[0], ele_tmp.ID[1])
                        new_entry.party = ele_tmp.party
                        new_entry.noEncID = ele_tmp.noEncID

                        # Re-encrypt
                        gr_rec, m_rec   = gmpy2.powmod(ele_tmp.ID[0], sk_2, workerClass.ElGamalInfo.p), gmpy2.powmod(msgID_dec, sk_2, workerClass.ElGamalInfo.p)

                        # Re-randomize
                        # Gen random number
                        s_2             = gmpy2.mpz_random(rand, workerClass.ElGamalInfo.p) + 1
                        # Use public keys and private key to encrypt value of 1
                        rer_val         = 1
                        # Encrypt with ElGamal public key of all workers further in mixnet
                        for EGPubKey in workerClass.ElGamalPubKeys:
                            if EGPubKey[0] > workerClass.roleNumber:
                                gr_s1, rer_val     = ElGamal.encrypt(workerClass.ElGamalInfo, rer_val, EGPubKey[1], s_2)
                        grm3, m_4       = gr_rec * gr_s1, m_rec * rer_val
                        grm3, m_4       = gmpy2.f_mod(grm3, workerClass.ElGamalInfo.p), gmpy2.f_mod(m_4, workerClass.ElGamalInfo.p)
                        new_entry.ID    = [grm3, m_4]
                        compareID.append(new_entry)

                    # Append output message
                    output_message.append(compareID)
                else:
                    new_entry = EntryStorage()
                    new_entry.newID = True
                    new_entry.party = msg_tmp.party
                    new_entry.noEncID = msg_tmp.noEncID
                    output_message.append(new_entry)

            # Last worker
            elif workerClass.roleNumber == (workerClass.numberParticipants - 1):
                if isinstance(msg_tmp, list):
                    for ele_tmp in msg_tmp:
                        new_entry = EntryStorage()

                        # Decrypt ElGamal
                        msgID_dec = ElGamal.decrypt(workerClass.ElGamalInfo, ele_tmp.ID[0], ele_tmp.ID[1])
                        new_entry.party = ele_tmp.party
                        new_entry.noEncID = ele_tmp.noEncID

                        # Re-encrypt
                        m_rec   = gmpy2.powmod(msgID_dec, sk_2, workerClass.ElGamalInfo.p)

                        # Check ID is new...
                        if m_rec == 1:
                            new_entry.newID = False
                            compareID = new_entry
                            break
                        else:
                            new_entry.newID = True
                            compareID = new_entry

                    # Check for 1's to signify value is already held?

                    # Append output message
                    output_message.append(compareID)
                else:
                    new_entry = EntryStorage()
                    new_entry.newID = True
                    new_entry.party = msg_tmp.party
                    new_entry.noEncID = msg_tmp.noEncID
                    output_message.append(new_entry)

        return output_message

    # Vertical Step 4
    # def ComparativeMixnetTwoEntry(self, workerClass, entry_1, entry_2):
    #     if workerClass.roleNumber == workerClass.numberParties:
    #  msg_data is a list of two entries
    def ComparativeMixnetScore(self, workerClass, msg_data):
        # Normalize input types: ensure msg_data is a list for downstream processing
        if not isinstance(msg_data, list):
            msg_data = [msg_data]
        output_message_tmp = []
        numberWorkers = workerClass.numberParticipants - workerClass.numberParties
        sk_2           = 2 #gmpy2.mpz_random(rand, workerClass.PaillierInfo.u ^ (1 / numberWorkers)) + 1
        diffScore      = [1, 1]  # Initialize diffScore
        new_entry = EntryStorage()
            
        # First worker
        if workerClass.roleNumber == workerClass.numberParties:
            assert len(msg_data) == 2
            entry_1 = msg_data[0]
            entry_2 = msg_data[1]
            # Calculate difference of input msg
            diffScore[0], diffScore[1] = entry_1.encValueInvert[0] * entry_2.encValue[0], entry_1.encValueInvert[1] * entry_2.encValue[1]
            # diffScore[0], diffScore[1] = entry_1.encValue[0], entry_1.encValue[1]
            diffScore[0], diffScore[1] = gmpy2.f_mod(diffScore[0], workerClass.ElGamalInfo.p), gmpy2.f_mod(diffScore[1], workerClass.ElGamalInfo.p)
            # Decrypt ElGamal
            diffScore_dec = ElGamal.decrypt(workerClass.ElGamalInfo, diffScore[0], diffScore[1])

            if diffScore_dec.bit_length() * sk_2 < workerClass.ElGamalInfo.p.bit_length():
                diffScore[0], diffScore_dec = gmpy2.powmod(diffScore[0], sk_2, workerClass.ElGamalInfo.p), gmpy2.powmod(diffScore_dec, sk_2, workerClass.ElGamalInfo.p)

            new_entry.encValue = [diffScore[0], diffScore_dec]
        else:
            assert len(msg_data) == 1
            entry_tmp = msg_data[0]

            if entry_tmp.encValue[1].bit_length() * sk_2 < workerClass.ElGamalInfo.p.bit_length():
                entry_tmp.encValue[0], entry_tmp.encValue[1] = gmpy2.powmod(entry_tmp.encValue[0], sk_2, workerClass.ElGamalInfo.p), gmpy2.powmod(entry_tmp.encValue[1], sk_2, workerClass.ElGamalInfo.p)
            # Decrypt ElGamal
            diffScore_dec = ElGamal.decrypt(workerClass.ElGamalInfo, entry_tmp.encValue[0], entry_tmp.encValue[1])
            
            diffScore = [entry_tmp.encValue[0], diffScore_dec]
            # new_entry.encValue = diffScore_dec
            # new_entry.value = entry_tmp.value
            #  If last worker decrypt with Paillier
            if workerClass.roleNumber == (workerClass.numberParticipants - 1):
                diffScore, _ = Paillier.decrypt(workerClass.PaillierInfo, diffScore_dec)
            # else:
            #     # Re-randomize
            #     # Gen random number
            #     s_2             = gmpy2.mpz_random(rand, workerClass.ElGamalInfo.p) + 1
            #     # Use public keys and private key to encrypt value of 1
            #     rer_val         = 1
            #     # Encrypt with ElGamal public key of all workers further in mixnet
            #     for EGPubKey in workerClass.ElGamalPubKeys:
            #         if EGPubKey[0] > workerClass.roleNumber:
            #             gr_s1, rer_val     = ElGamal.encrypt(workerClass.ElGamalInfo, rer_val, EGPubKey[1], s_2)
            #     grm3, m_4       = entry_tmp.encValue[0] * gr_s1, diffScore_dec * rer_val
            #     grm3, m_4       = gmpy2.f_mod(grm3, workerClass.ElGamalInfo.p), gmpy2.f_mod(m_4, workerClass.ElGamalInfo.p)
            #     diffScore         = [grm3, m_4]

            # Set new encrypted value (after decryption, re-randomization)
            new_entry.encValue = diffScore
            # print(f"DEBUG: diff value = {diffScore}")
            
        # Store and append
        output_message_tmp.append(new_entry)

        # Permute output messages
        # perm_inds = list(range(len(output_message_tmp)))
        # random.shuffle(perm_inds)                   # Shuffle in-place
        # output_message = [output_message_tmp[i] for i in perm_inds]

        return(output_message_tmp)


   # Vertical Step 4.1 (version 2)
    def _process_first_worker_entry(self, entry_2, entry_1, workerClass):
        try:
            numberWorkers = workerClass.numberParticipants - workerClass.numberParties
            sk_2           = 2 #gmpy2.mpz_random(rand, workerClass.ElGamalInfo.p ^ (1 / numberWorkers)) + 1
            new_entry = EntryStorage()
            # Calculate difference of input msg
            diffScore = entry_1.encValue[0] * entry_2.encValueInvert[0], entry_1.encValue[1] * entry_2.encValueInvert[1]
            diffScore = gmpy2.f_mod(diffScore[0], workerClass.ElGamalInfo.p), gmpy2.f_mod(diffScore[1], workerClass.ElGamalInfo.p)
            # print(f"DEBUG: First worker initial diffScore = {diffScore}")
            # diffScore[0], diffScore[1] = gmpy2.invert(entry_1.encValue[0], workerClass.ElGamalInfo.p), gmpy2.invert(entry_1.encValue[1], workerClass.ElGamalInfo.p)
            diffScore_dec = ElGamal.decrypt(workerClass.ElGamalInfo, diffScore[0], diffScore[1])
            
            if diffScore_dec.bit_length() * sk_2 < workerClass.ElGamalInfo.p.bit_length():
                diffScore[0], diffScore_dec = gmpy2.powmod(diffScore[0], sk_2, workerClass.ElGamalInfo.p), gmpy2.powmod(diffScore_dec, sk_2, workerClass.ElGamalInfo.p)

            # Randomize
            # rr_gr, rr_m = gmpy2.powmod(diffScore[0], sk_2, workerClass.ElGamalInfo.p), gmpy2.powmod(diffScore_dec, sk_2, workerClass.ElGamalInfo.p)
            new_entry.equalityCheck = [diffScore[0], diffScore_dec]

            new_entry.encValue = entry_1.encValue
            new_entry.encValueInvert = entry_1.encValueInvert
            new_entry.ID = entry_1.ID
            new_entry.noEncID = entry_1.noEncID
            return new_entry
        except Exception as e:
            log.error(f"Error processing first worker entry: {e}")
            raise

    def _process_other_worker_entry(self, entry_tmp, workerClass):
        try:
            new_entry = EntryStorage()
            numberWorkers = workerClass.numberParticipants - workerClass.numberParties
            sk_2           = 2 #gmpy2.mpz_random(rand, workerClass.ElGamalInfo.p ^ (1 / numberWorkers)) + 1
            # Decrypt ElGamal
            # entry_tmp.equalityCheck[0], entry_tmp.equalityCheck[1] = gmpy2.powmod(entry_tmp.equalityCheck[0], sk_2, workerClass.ElGamalInfo.p), gmpy2.powmod(entry_tmp.equalityCheck[1], sk_2, workerClass.ElGamalInfo.p)
            if entry_tmp.equalityCheck[1].bit_length() * sk_2 < workerClass.ElGamalInfo.p.bit_length():
                entry_tmp.equalityCheck[0], entry_tmp.equalityCheck[1] = gmpy2.powmod(entry_tmp.equalityCheck[0], sk_2, workerClass.ElGamalInfo.p), gmpy2.powmod(entry_tmp.equalityCheck[1], sk_2, workerClass.ElGamalInfo.p)
            # Randomize
            # rr_gr, rr_m = gmpy2.powmod(entry_tmp.equalityCheck[0], sk_2, workerClass.ElGamalInfo.p), gmpy2.powmod(entry_tmp.equalityCheck[1], sk_2, workerClass.ElGamalInfo.p)
            diffScore = ElGamal.decrypt(workerClass.ElGamalInfo, entry_tmp.equalityCheck[0], entry_tmp.equalityCheck[1])

            new_entry.equalityCheck = [entry_tmp.equalityCheck[0], diffScore]
            # print(f"DEBUG: before Paillier decrypt diffScore = {diffScore}")
            #  If last worker decrypt with Paillier
            if workerClass.roleNumber == (workerClass.numberParticipants - 1):
                # diffScore_dec = gmpy2.f_mod(diffScore_dec, workerClass.PaillierInfo.pkey.usquare)
                diffScore, _ = Paillier.decrypt(workerClass.PaillierInfo, diffScore)

                new_entry.equalityCheck = diffScore
            # else:
                # Re-randomize
                # Gen random number
                # s_2             = gmpy2.mpz_random(rand, workerClass.ElGamalInfo.p) + 1
                # Use public keys and private key to encrypt value of 1
                # rer_val         = 1
                # Encrypt with ElGamal public key of all workers further in mixnet
                # for EGPubKey in workerClass.ElGamalPubKeys:
                #     if EGPubKey[0] > workerClass.roleNumber:
                #         gr_s1, rer_val     = ElGamal.encrypt(workerClass.ElGamalInfo, rer_val, EGPubKey[1], s_2)
                # grm3, m_4       = entry_tmp.equalityCheck[0] * gr_s1, diffScore_dec * rer_val
                # grm3, m_4       = gmpy2.f_mod(grm3, workerClass.ElGamalInfo.p), gmpy2.f_mod(m_4, workerClass.ElGamalInfo.p)
                # diffScore         = [grm3, m_4]

            # Set new encrypted value (after decryption, re-randomization)
            new_entry.encValue = entry_tmp.encValue
            new_entry.encValueInvert = entry_tmp.encValueInvert
            new_entry.ID = entry_tmp.ID
            new_entry.noEncID = entry_tmp.noEncID
            
            return new_entry
        except Exception as e:
            log.error(f"Error processing other worker entry: {e}")
            raise

    def ComparativeMixnetScoreBatch(self, workerClass, msg_data, max_workers=None):
        import time
        start_time = time.time()
        
        # Normalize input types: ensure msg_data is a list for downstream processing
        if not isinstance(msg_data, list):
            msg_data = [msg_data]
        

        
        # Determine optimal number of threads
        if max_workers is None:
            max_workers = 2 * multiprocessing.cpu_count() - 1
    
        
        try:
            # First worker
            if workerClass.roleNumber == workerClass.numberParties:
                assert len(msg_data) == 1
                entry_1 = msg_data[0]
                
                # Prepare data for threading
                heap_entries = list(workerClass.ID_store.sorted_list)
                # log.info(f"Processing {len(heap_entries)} heap entries in parallel")
                
                # Use ThreadPoolExecutor for parallel processing
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    # Submit all tasks
                    futures = [executor.submit(self._process_first_worker_entry, entry_2, entry_1, workerClass) 
                              for entry_2 in heap_entries]
                    
                    # Collect results
                    output_message_tmp = [future.result() for future in futures]
            else:
                # Prepare data for threading
                msg_entries = list(msg_data)
                # log.info(f"Processing {len(msg_entries)} message entries in parallel")
                
                # Use ThreadPoolExecutor for parallel processing
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    # Submit all tasks
                    futures = [executor.submit(self._process_other_worker_entry, entry_tmp, workerClass) 
                              for entry_tmp in msg_entries]
                    
                    # Collect results
                    output_message_tmp = [future.result() for future in futures]

            # Permute output messages
            # perm_inds = list(range(len(output_message_tmp)))
            # random.shuffle(perm_inds)                   # Shuffle in-place
            # output_message = [output_message_tmp[i] for i in perm_inds]

            end_time = time.time()
            # log.info(f"ComparativeMixnetScoreBatch completed in {end_time - start_time:.2f} seconds")
            
            return(output_message_tmp)
            
        except Exception as e:
            log.error(f"Error in ComparativeMixnetScoreBatch: {e}")
            raise