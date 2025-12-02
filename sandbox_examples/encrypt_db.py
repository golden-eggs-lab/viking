from party import Party
from communication_helper import CommunicationEnvironment
from multiprocessing import Barrier, Process, Lock, Event
from security.elgamal import ElGamal
from security.paillier import Paillier
from worker import paillier_send
import time
import numpy as np
import gmpy2
import seal         # Microsoft SEAL
import sealp        # Microsoft SealPIR
import pickle 
import struct

def binary_to_uint8(bytestring, db_enc):
    expected_byte_len = len(bytestring) - 2

    if expected_byte_len < 256:
        # If byte length 255 (add 0 in front)
        db_enc.append(0)

    for byte in range(expected_byte_len):
        db_enc.append(bytestring[byte + 2])
    return db_enc

def encrypt_database(party_instance, database):
    # Initialize encrypted db
    db_enc      = []
    db_enc_pair = []
    expected_byte_len = 2048 // 8

    for value in database:
        enc_ele_tmp     = gmpy2.mpz(value)

        # Encrypt with Paillier
        r_p             = Paillier.gen_r(party_instance.PaillierPubKeys[0])
        enc_ele_tmp_p   = Paillier.encrypt(party_instance.PaillierPubKeys[0], enc_ele_tmp, r=r_p)

        # Inputs: encrypt(self, v, pkey=None, r=None
        r_party             = ElGamal.gen_r(party_instance.ElGamalInfo)
        _, enc_ele_tmp_e    = ElGamal.encrypt(party_instance.ElGamalInfo, enc_ele_tmp_p, party_instance.ElGamalPubKeys[0][1], r_party)
        _, enc_ele_tmp_ee   = ElGamal.encrypt(party_instance.ElGamalInfo, enc_ele_tmp_e, party_instance.ElGamalPubKeys[1][1], r_party)
        enc_val_tmp         = ElGamal.encrypt(party_instance.ElGamalInfo, enc_ele_tmp_ee, party_instance.ElGamalPubKeys[2][1], r_party)
        enc_val_out         = [enc_val_tmp[0], enc_val_tmp[1]]
        db_enc_pair.append(enc_val_out)

        # Save encrypted pair to encrypted db
        bin_tmp_01 = gmpy2.to_binary(enc_val_out[0])
        bin_tmp_02 = gmpy2.to_binary(enc_val_out[1])
        db_enc = binary_to_uint8(bin_tmp_01, db_enc)
        db_enc = binary_to_uint8(bin_tmp_02, db_enc)

    return db_enc, db_enc_pair

def setup_db():
    # Initialize communication envrionment
    # lock = Lock()
    num_parties = 1
    num_workers = 3
    CE   = CommunicationEnvironment(['2001', '3001', '3002', '3003'], num_parties, num_workers, ['party', 'worker', 'worker', 'worker'])#, lock)
    QueryWeights = np.asarray([1, 1, 1, 1, 1, 1, 1, 1, 1])
    k = 2
    start_time = time.time()
    party01 = Party(0, 'party', 'vertical', 'secure', CE, QueryWeights, k, startTime = start_time)

    # Load db
    file_path = './raisin_preprocess_norm_l1.csv'
    party01.ReadDataVertical(file_path)
    party01.CalculateScores()

    # Initialize db for pir
    db_pir = party01.scoresOT.astype('int')
    print('Max val: ' + str(np.max(db_pir)))

    # Define security environment
    e_key_len   = 224                         # NIST recommended: 224
    e_bit_len   = 2048                        # NIST recommended: 2048

    # Generate EG info for each worker
    eg_worker_info = []
    eg_worker_dec  = []
    for w in range(3):
        eg_tmp = ElGamal(e_key_len, e_bit_len)
        if w == 0:
            party01.ElGamalInfo = eg_tmp
        eg_tmp.key_gen()
        key_tmp = eg_tmp.get_ekey()
        eg_worker_info.append([w, key_tmp.k])
        eg_worker_dec.append(eg_tmp)

    # Generate Paillier key
    p_bit_len   = int(np.sqrt(e_bit_len))
    pa01        = Paillier(p_bit_len)
    count       = 0
    while True:
        pa01.key_gen()
        if (num_parties + 1) * pa01.usquare < eg_tmp.p:
            ratio01 = (num_parties + 1) * pa01.usquare / eg_tmp.p
            ratio02 = (pa01.usquare ** (num_parties + 1)) / eg_tmp.p
            break
        elif count == 10:
            break
        count += 1

    PaillierSend = paillier_send()
    PaillierSend.pkey = pa01.get_pkey()
    party01.PaillierPubKeys.append(PaillierSend)

    party01.ElGamalPubKeys  = eg_worker_info
    db_pir_enc, db_enc_pair = encrypt_database(party01, db_pir)

    return db_pir, db_pir_enc, db_enc_pair, party01, eg_worker_dec, pa01

def pir(db_pir):
    # Initialize bfv encryption parameters
    scheme_type_in  = seal.scheme_type.bfv                           # bfv
    enc_params      = seal.EncryptionParameters(scheme_type_in)

    N       = 4096
    logt    = 20
    sealp.gen_encryption_params(N, logt, enc_params)
    sealp.verify_encryption_params(enc_params)

    # enc_params.save('enc_p.bin')
    # b = enc_params.load('enc_p.bin')
    # print(b)
    # enc_params2 = seal.EncryptionParameters(scheme_type_in)

    size_per_item   = 512
    number_of_items = len(db_pir) // size_per_item
    print('Size per item: ' + str(size_per_item))
    print('Number of items: ' + str(number_of_items))
    d               = 2
    use_symmetric               = False
    use_batching                = True
    use_recursive_mod_switching = True
    pir_params                  = sealp.PirParams()
    sealp.gen_pir_params(number_of_items, size_per_item, d, enc_params, pir_params,
        use_symmetric, use_batching, use_recursive_mod_switching)

    # Display encryption parameters
    sealp.print_seal_params(enc_params)
    sealp.print_pir_params(pir_params)

    # Initialize client
    client              = sealp.PIRClient(enc_params, pir_params)
    client_galois_keys  = client.generate_galois_keys()

    # Save Galois keys
    # galois_keys_str = sealp.serialize_galoiskeys(client_galois_keys)
    gk_context = seal.SEALContext(enc_params)
    # server_galois_keys = sealp.deserialize_galoiskeys(galois_keys_str, gk_context)
    client_galois_keys.save('gk01.bin')
    gk = seal.GaloisKeys()
    gk.load(gk_context, 'gk01.bin')

    # Initialize server
    server = sealp.PIRServer(enc_params, pir_params)
    server.set_galois_key(0, gk)

    # Setup db
    print('db_enc len: ' + str(len(db_pir)))
    server.wrap_database(db_pir, number_of_items, size_per_item)
    server.preprocess_database()

    # Choose index in db
    ele_index   = np.random.randint(900)
    index = client.get_fv_index(ele_index)      # index of FV plaintext
    offset = client.get_fv_offset(ele_index)    # offset in FV plaintext

    # Generate query (client)
    query = client.generate_query(index)

    # Generate serialized query (client)
    client_string = sealp.StringStreamR()
    server_string = sealp.StringStreamR()
    output_size = client.generate_serialized_query(index, client_string)

    # Deserialize query (server)
    print(client_string)
    b = pickle.dumps(client_string)
    print('PICKLED')
    c = pickle.loads(b)
    print('DEPICKLED')
    print(c)
    query = server.deserialize_query(client_string)

    # Query processing (server)
    reply = server.generate_reply(query, 0)

    # Serialize reply (server)
    reply_size = server.serialize_reply(reply, server_string)

    # Test pickling of server_string
    # reply_wrap = sealp.PirReply_wrap()
    # reply_wrap.reply_return = reply
    b = pickle.dumps(server_string)
    server_string = pickle.loads(b)
    # reply_new = reply_bnew.reply_return

    # Deserialize response
    reply_new = client.deserialize_reply(server_string)

    # Decode response (client)
    elems = client.decode_reply(reply_new, offset)

    # Check received values...
    start_ind   = ele_index * size_per_item
    end_ind     = (ele_index + 1) * size_per_item
    expected    = db_pir[start_ind:end_ind]

    return elems, ele_index

# Convert values to encrypted pair
def to_encrypted_pair(party_instance, elems, db_pir, db_pir_enc, db_enc_pair, ele_index, pa01):
    byte_tmp    = bytearray(elems)
    b_tmp       = bytearray(b'\x01\x01')

    byte_tmp01 = byte_tmp[:256]
    byte_tmp02 = byte_tmp[256:]

    byte_tmp01[0:0] = b_tmp
    byte_tmp02[0:0] = b_tmp

    c0 = gmpy2.from_binary(bytes(byte_tmp01))
    c1 = gmpy2.from_binary(bytes(byte_tmp02))

    # Decrypt and check values
    msg_tmp = ElGamal.decrypt(eg_worker_dec[0], c0, c1)
    msg_tmp = ElGamal.decrypt(eg_worker_dec[1], c0, msg_tmp)
    msg_tmp = ElGamal.decrypt(eg_worker_dec[2], c0, msg_tmp)
    msg     = Paillier.decrypt(pa01, msg_tmp)
    msg     = msg[0]
    print(msg, db_pir[ele_index], sep='\t')
    assert(msg == db_pir[ele_index])

# main()
db_pir, db_pir_enc, db_enc_pair, party01, eg_worker_dec, pa01   = setup_db()
elems, ele_index                = pir(db_pir_enc)
to_encrypted_pair(party01, elems, db_pir, db_pir_enc, db_enc_pair, ele_index, pa01)



# Test...
# rand = gmpy2.random_state(hash(gmpy2.random_state()))
# test_int = gmpy2.mpz_urandomb(rand, 2048)



# bin_tmp_01 = gmpy2.to_binary(test_int)
# print(bin_tmp_01)
# db_enc = []
# db_enc = binary_to_uint8(bin_tmp_01, db_enc)
# byte_tmp = bytearray(db_enc)
# print(byte_tmp[0])
# b_tmp = bytearray(b'\x01\x01')
# byte_tmp[0:0] = b_tmp
# ct = gmpy2.from_binary(bytes(byte_tmp))
# print(test_int, ct, sep='\n\n')