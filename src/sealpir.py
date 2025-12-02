import seal
import sealp
import logging

log = logging.getLogger('fedtopk')

class SealPIR():
	def gen_pir_params(db_len, bit_len, num_ciphertexts=2):
		byte_size = 8 	# Each ciphertext broken down into uint8s

		# Initialize bfv encryption parameters
		scheme_type_in  = seal.scheme_type.bfv                           # bfv
		enc_params      = seal.EncryptionParameters(scheme_type_in)

		N       = 4096  			# Degree of polynomial
		logt    = 20 				# Plaintext modulus
		sealp.gen_encryption_params(N, logt, enc_params)
		sealp.verify_encryption_params(enc_params)

		size_per_item   = (bit_len * num_ciphertexts) // byte_size
		number_of_items = db_len # // size_per_item
		log.debug('SealPIR size per item: ' + str(size_per_item))
		log.debug('SealPIR number of items: ' + str(number_of_items))
		d               = 2
		use_symmetric               = False 		# True or False?
		use_batching                = True
		use_recursive_mod_switching = True
		pir_params                  = sealp.PirParams()
		sealp.gen_pir_params(number_of_items, size_per_item, d, enc_params, pir_params,
			use_symmetric, use_batching, use_recursive_mod_switching)
		return enc_params, pir_params

	def client_init(enc_params, pir_params):
		# Initialize client
		client 	= sealp.PIRClient(enc_params, pir_params)

		return client

	def server_init(enc_params, pir_params):
		# Initialize server
		server 	= sealp.PIRServer(enc_params, pir_params)

		return server

	def client_gen_gallois_keys(client):
		return client.generate_galois_keys()

	# def server_gen_pir_db(client_ind, client_galois_keys):
	# 	# Set database
	# 	server.set_galois_key(client_ind, client_galois_keys)

	# 	# Setup db
	# 	server.wrap_database(db_pir, number_of_items, size_per_item)
	# 	server.preprocess_database()

	def client_gen_query(client, ele_index):
		# Choose index in db
		index = client.get_fv_index(ele_index)      # index of FV plaintext
		offset = client.get_fv_offset(ele_index)    # offset in FV plaintext

		# Generate query (client)
		query = client.generate_query(index)

		# Generate serialized query (client)
		client_string = sealp.StringStreamR()
		output_size = client.generate_serialized_query(index, client_string)

		return query, client_string

	def server_gen_reply(client_string):
		# Deserialize query (server)
		query = server.deserialize_query(client_string)

		# Query processing (server)
		reply = server.generate_reply(query, 0)

		# Serialize reply (server)
		reply_size = server.serialize_reply(reply, server_string)

		return reply

	def client_decrypt_reply(client, reply, offset):
	   # Decode response (client)
		elems = client.decode_reply(reply, offset)

		return elems

class PirParams():
	def __init__(self):
		self.enable_symmetric 		= False
		self.enable_batching		= True
		self.enable_mswitching 		= True
		self.ele_num 				= 0
		self.ele_size 				= 9
		self.elements_per_plaintext = 0
		self.num_of_plaintexts 		= 0
		self.d 						= 2 
		self.expansion_ratio 		= 1
		self.nvec 					= None # List..?
		self.slot_count 			= 0

	def set_params(self, pir_params):
		self.enable_symmetric 		= pir_params.enable_symmetric
		self.enable_batching		= pir_params.enable_batching
		self.enable_mswitching 		= pir_params.enable_mswitching
		self.ele_num 				= pir_params.ele_num
		self.ele_size 				= pir_params.ele_size
		self.elements_per_plaintext = pir_params.elements_per_plaintext
		self.num_of_plaintexts 		= pir_params.num_of_plaintexts
		self.d 						= pir_params.d
		self.expansion_ratio 		= pir_params.expansion_ratio
		self.nvec 					= pir_params.nvec
		self.slot_count 			= pir_params.slot_count





















