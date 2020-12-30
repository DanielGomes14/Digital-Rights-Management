import requests
import logging
import binascii
import json
import os
import PyKCS11
import random
import subprocess
import time
import sys
import base64
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as pd
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography import x509   
import os
from datetime import datetime,timedelta 
lib = '/usr/local/lib/libpteidpkcs11.so'

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)
logger.setLevel(logging.ERROR)

SERVER_URL = 'http://127.0.0.1:8080'
class License:

	def __init__(self,media_id,start_date,end_date):
		self.start_date = start_date
		self.end_date = end_date
		self.media_id=media_id
	

class Client:
	def __init__(self):
		"""Representation of the client."""

		self.ciphers = ['AES', '3DES', 'ChaCha20']			#available ciphers
		self.digests = ['SHA-512', 'SHA-256']				#available digests
		self.ciphermodes = ['CBC', 'CTR']					#available modes
		self.srvr_publickey = None							
		self.cipher = None									#current cipher
		self.digest = None									#current digest
		self.ciphermode = None								#current mode
		self.dh_parameters = None							
		self.trusting_chain=[]								#server certificate chain
		self.issuers_certs={}								#CA certificates
		self.crls_list=[]
		self.load_certs('../Certs/')
		self.load_crl('../Certs/')
		self.read_cc()
		self.licenses = {} 									# media_id : certificate 
		self.state='INITIAL'
	
	def validate_certificate(self, certificate):
		"""Verifies if the certificate is up to date """
		
		dates = (certificate.not_valid_before.timestamp(),certificate.not_valid_after.timestamp())
		date_now=datetime.now().timestamp()
		return dates[0]< date_now < dates[1]

	def validate_server_purpose(self,certificate):
		"""Validates the server certificate purpose  """

		server_auth = x509.oid.ExtendedKeyUsageOID.SERVER_AUTH
		extended_key_usages = certificate.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
		return any(extension for extension in extended_key_usages.value if extension.dotted_string == server_auth.dotted_string)
	


	def validate_signature(self,issuer,subject):
		"""
		Validate the Signature of a Certificate
		The issuer parameter represents the certificate of the issuer
		The subject parameter represents the certificate we want to verify
		"""
		issuer_pub_key = issuer.public_key()
		try:
			issuer_pub_key.verify(
				subject.signature,
				subject.tbs_certificate_bytes,
				pd.PKCS1v15(),
				subject.signature_hash_algorithm,
			)
			return True
		except:
			logger.error("Could not Validate the Signature of the Certificate")
			return False
	


	
	def validate_server_signature(self,recv_key, signature):
		"""
		Validate if the server public key for Diffie Hellmann is valid, in order to avoid MiTM
		"""
		try:
			self.server_cert.public_key().verify(
				signature,
				recv_key,
				pd.PSS(
				mgf=pd.MGF1(hashes.SHA256()),
				salt_length=pd.PSS.MAX_LENGTH
				),hashes.SHA256()
			)
			logger.info("Server Signature OK")
			return True
		except:
			logger.error("Server Signature Wrong")
			return False
	


	def crl_validation(self, cert):
		"""Validate if certificate is in list of the revocated certificates"""
		return all(crl.get_revoked_certificate_by_serial_number(cert.serial_number) == None for crl in self.crls_list)
	

	def validate_cert_chain(self):
		"""Checks if the server certificate chain is valid """

		chain = self.trusting_chain
		if len(self.trusting_chain) <= 1:
			return False 
		for i in range(0, len(chain) - 1):

			if not self.validate_certificate(chain[i]):
				return False

			#verifies if the signatures are valid 
			if not self.validate_signature(chain[i+1], chain[i]):
				return False
			
			# verifies if the certificate is not on a CRL 
			if not self.crl_validation(chain[i]):
				return False
			
		return True 

	def load_certs(self, path):
		"""Loads Certificates from disk"""
		try:
			with os.scandir(path) as it:
				for entry in it:
					if entry.name.endswith('crt') and entry.is_file():
						with open(path + entry.name,'rb') as cert:
							data=cert.read()
							cr = x509.load_pem_x509_certificate(data)
							if self.validate_certificate(cr):
								self.issuers_certs[cr.subject.rfc4514_string()] = cr
							
				logger.info("Certicates loaded!")
		except:
			logger.error("Could not load certificates.Make sure to run this file on the /client directory")
	
	
	def load_crl(self,path):
		"""Loads CRLs from disk"""
		try:
			with os.scandir(path) as it:
				for entry in it:
					if entry.name.endswith('crl') and entry.is_file():
						with open(path + entry.name,'rb') as f:
							crl_data = f.read()
							crl = x509.load_der_x509_crl(crl_data)
							self.crls_list.append(crl)
						
				logger.info("Certicates loaded!")
		except:
			logger.error("Could not read Path!Make sure to run this file on the /client directory")


	def build_cert_chain(self,certificate):
		"""Builds the certificate chain of a given certificate"""
		chain = []
		last = None
		logger.info("Starting to build trusting chain..")
		
		while True:
			if last == certificate:
				self.trusting_chain = []
				return
			last = certificate
			
			chain.append(certificate)
			issuer = certificate.issuer.rfc4514_string()
			subject = certificate.subject.rfc4514_string()
			
			if issuer == subject and issuer in self.issuers_certs:
				break
			
			if issuer in self.issuers_certs:
				certificate = self.issuers_certs[issuer]
		logger.info("Chain Built with success")
		self.trusting_chain = chain

	def has_negotiated(self):
		"""Checks if the client has already negotiated algs"""
		return not (self.cipher is None or self.digest is None)

	def negotiate_algs(self):
		"""
		Negotiates algorithms with the server
		Sends all the available algorithms and waits for the server to choose one
		"""

		data = {
			'method': "NEGOTIATE_ALG",
			'ciphers': self.ciphers,
			'digests': self.digests,
			'ciphermodes': self.ciphermodes
		}
		request = requests.post(f'{SERVER_URL}/api/protocols',json=data, headers={'Content-Type': 'application/json'})



		response = json.loads(request.text)
		
		if response['method'] == 'NACK':
			logger.info('ERROR NEGOTIATING ALGORITHMS')
		else:
			logger.info('NEGOTIATED ALGORITHMS WITH SUCCESS')
			self.session_id = response['id']
			self.cipher, self.digest, self.ciphermode = response['cipher'], response['digest'], response['mode']
			
			cert = base64.b64decode(response['cert'])
			cert = x509.load_pem_x509_certificate(cert)
			self.build_cert_chain(cert)
			if self.validate_cert_chain() and self.validate_server_purpose(cert):
				logger.info("Server Certificate OK")
				self.server_cert = cert
				self.state = 'NEGOTIATE_ALG'
			else:
				logger.info("Certificate is not valid")
				exit(1)		# TODO: ver

			#self.server_cert=cert

	def dh_start(self):
		""" Diffie-Helman: get parameters and generate public and private key """
		if self.state=='NEGOTIATE_ALG':
			# GET request for the parameters and server public key
			headers = None
			if self.session_id != None:
				headers = {
					'session_id':str(self.session_id)
				}
			response = requests.get(f'{SERVER_URL}/api/key',headers=headers)
			
			logger.info('Received parameters and Public Key with sucess')
			data = json.loads(response.text)
			p = data['p']
			g = data['g']

			# generates public and private key using the parameters
			pn = dh.DHParameterNumbers(p, g)
			self.dh_parameters = pn.parameters()
			self.private_key = self.dh_parameters.generate_private_key()
			self.public_key = self.private_key.public_key()
			
			#stores server public key
			received_key = data['pub_key'].encode('latin')
			self.srvr_publickey = load_pem_public_key(received_key)
			signature = data['signature'].encode('latin')
			
			if self.validate_server_signature(received_key,signature):
				self.state = 'DH_START'
				logger.info("Signatures OK")
			else:
				logger.error("Signatures wrong")
		else:
			return False

		

	def dh_exchange_key(self):
		""" Exchange keys with the server"""
		
		if self.state =='DH_START':


			logger.info('Sending POST Request to exchange DH Shared key')
			key = self.public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

			data = {
				'method': 'KEY_EXCHANGE',
				'pub_key': key
			}

			# POST request sending public key
			request = requests.post(f'{SERVER_URL}/api/key', json=data, headers={'Content-Type': 'application/json','session_id' : str(self.session_id)})
			data = json.loads(request.text)
			method = data['method']
			
			if method == 'ACK':
				logger.info('Server confirmed the exchange')
				self.shared_key = self.private_key.exchange(self.srvr_publickey)
				self.state='KEY_EXCHANGE'
			else:
				logger.error('Could not exchange a key with the server')
		else:
			return False

	def encrypt_message(self, text,key):
		"""Encrypts message with a symmetric key"""
		iv = os.urandom(16)
		cipher = None
		algorithm,iv = None,None
		mode = None
		
		enc_shared_key = key[len(key)//2:]

		if self.cipher == 'AES':
			algorithm = algorithms.AES(enc_shared_key)
		elif self.cipher == '3DES':
			algorithm = algorithms.TripleDES(enc_shared_key)
		else:
			iv = os.urandom(16)
			algorithm = algorithms.ChaCha20(enc_shared_key, iv)
			logger.error('Algorithm not suported')
		
		if self.cipher != 'ChaCha20':
			# with ChaCha20 we do not pad the data
			iv = os.urandom(algorithm.block_size//8)
			if self.ciphermode == 'CBC':
				mode = modes.CBC(iv)
			elif self.ciphermode == 'CTR':
				mode = modes.CTR(iv)
			padder = padding.PKCS7(algorithm.block_size).padder()
			padded_data = padder.update(text)
			padded_data += padder.finalize()
			text=padded_data
		cipher = Cipher(algorithm, mode=mode)
		encryptor = cipher.encryptor()
		cryptogram = encryptor.update(text) + encryptor.finalize()

		return cryptogram, iv

	def decrypt_message(self, cryptogram, iv,key):
		"""Decrypts messages with a symmetric key"""

		cipher = None
		algorithm = None
		mode = None
		enc_shared_key=key[len(key)//2:]
		if self.cipher == 'AES':
			algorithm = algorithms.AES(enc_shared_key)
		elif self.cipher == '3DES':
			algorithm = algorithms.TripleDES(enc_shared_key)
		elif self.cipher == 'ChaCha20':
			# in this case the nonce is the iv
			if iv != None:
				algorithm = algorithms.ChaCha20(enc_shared_key, iv)
		else:
			logger.debug('Algorithm not suported')

		# with ChaCha20 we do not pad the data
		if self.ciphermode == 'CBC':
			mode = modes.CBC(iv)
		elif self.ciphermode == 'CTR':
			mode = modes.CTR(iv)
		
		cipher = Cipher(algorithm, mode=mode)
		decryptor = cipher.decryptor()
		if self.cipher == 'ChaCha20':
			return decryptor.update(cryptogram) + decryptor.finalize()
		else:
			padded_data = decryptor.update(cryptogram) + decryptor.finalize()
			unpadder = padding.PKCS7(algorithm.block_size).unpadder()
			text = unpadder.update(padded_data)
			text += unpadder.finalize()
			return text

	
	def receive_message(self,response):

		iv = base64.b64decode(response['iv'])
		hmac = base64.b64decode(response['hmac'])
		salt = base64.b64decode(response['salt'])
		msg = base64.b64decode(response['message'])
		
		key, _ = self.derive_key(self.shared_key,salt)

		return msg,key,iv,salt,hmac


	def read_cc(self):
		"""Reads citizen card certificates and private key"""

		print("-------+---------")
		pkcs11 = PyKCS11.PyKCS11Lib()
		pkcs11.load(lib)
		self.slots =pkcs11.getSlotList()
		for slot in self.slots:
			print(pkcs11.getTokenInfo(slot))
		
		#slot=pkcs11.getSlotList(tokenPresent=Tru)[0]
		self.session=pkcs11.openSession(slot)
		all_attributes = list(PyKCS11.CKA.keys())
		all_attributes = [e for e in all_attributes if isinstance(e, int)]
		
		obj = self.session.findObjects([(PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION CERTIFICATE')])[0]
		attributes = self.session.getAttributeValue(obj, all_attributes)
		attributes = dict(zip(map(PyKCS11.CKA.get, all_attributes), attributes))
		
		self.certificate=x509.load_der_x509_certificate(bytes(attributes['CKA_VALUE']))
		cc_num = self.certificate.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
		self.private_key_cc = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
		self.mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)


	def sign_message(self,text):
		"""Signs message with private key"""
		mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
		signature = bytes(self.session.sign(self.private_key_cc, text, mech))
		#self.certificate.public_key().verify(signature,text, pd.PKCS1v15(), hashes.SHA1())
		return signature

	def chunk_identification(self, chunk_id, media_id):
		"""Generates a key that identifies the given chunk and media"""
		return (self.shared_key.decode('latin') + media_id + str(chunk_id)).encode('latin')


	def start_challenge(self):
		"""
		Client sends to server his certificate in order to validate it,
		along side with a challenge. 
		"""
		if self.state=='KEY_EXCHANGE':

			logger.info("Starting Challenge")
			nonce = os.urandom(16)
			self.challenge_nonce = nonce
			key, salt = self.derive_key(self.shared_key)
			if self.session_id != None:
				headers = {
					'Content-Type': 'application/json',
					'session_id' : str(self.session_id)
					}	
			message = json.dumps({
				'method': 'START_CHALLENGE',
				'nonce': nonce.decode('latin'), 
				'cert': self.certificate.public_bytes(serialization.Encoding.PEM).decode('latin'),
			}).encode('latin')		
			data,iv = self.encrypt_message(message,key)
			
			logger.info("Sucessfuly encrypted challenge and certificate")
			
			message = {
				'data': base64.b64encode(data),
				'iv': base64.b64encode(iv),
				'hmac': base64.b64encode(self.add_hmac(data,key)),
				'salt': base64.b64encode(salt)
			}
			
			logger.info("Sending POST Challenge and Client Certificate")
			request = requests.post(f'{SERVER_URL}/api',json=message, headers=headers)
			
			response = json.loads(request.text)
			message, key, iv, salt, hmac = self.receive_message(response)
			#iv = base64.b64decode(response['iv'])
			#hmac = base64.b64decode(response['hmac'])
			#salt = base64.b64decode(response['salt'])
			#msg = base64.b64decode(response['message'])
			
			#key, _ = self.derive_key(self.shared_key,salt)
			if not self.verify_hmac(hmac,message,key):
				exit(0)
			else:
				logger.info("HMAC OK")
				message = self.decrypt_message(message,iv,key)
				message = json.loads(message)
				nonce = message['snonce'].encode('latin')
				nonce2 = message['nonce2'].encode('latin')
				self.state='START_CHALLENGE'
				if self.verify_challenge(nonce):
					self.accept_challenge(nonce2)
				else:
					return False

		else:
			return False	



	def verify_challenge(self,crypt):
		"""Verifies the server response to the challenge"""
		try:
			self.server_cert.public_key().verify(
				crypt,
				self.challenge_nonce,
				pd.PSS(
				mgf=pd.MGF1(hashes.SHA256()),
				salt_length=pd.PSS.MAX_LENGTH),
				hashes.SHA256()
			)
			logger.info("Challenge OK")
			return True
		except:
			logger.error("Challenge wrong. Comms Compromised")
			return False

	def accept_challenge(self,nonce2):
		"""Accepts Server challenge and sends signed Nonce.
			Also it is sent the protocols that the client is using, in order to verify if they were not downgraded
		"""
		logger.info("Sending POST to accept Challenge")
		if self.state=='START_CHALLENGE':
			snonce2 = self.sign_message(nonce2)
			self.challenge_nonce2 = snonce2
			key, salt = self.derive_key(self.shared_key)
			if self.session_id != None:
				headers = {
					'Content-Type': 'application/json',
					'session_id': str(self.session_id)
				}
			message = json.dumps({
				'method': 'ACCEPT_CHALLENGE',
				'snonce2':snonce2.decode('latin'),
				'protocols':json.dumps({'cipher':self.ciphers,'mode':self.ciphermodes,'digest':self.digests})
			}).encode('latin')
			data, iv = self.encrypt_message(message,key)
			
			logger.info("Sucessfuly encrypted challenge,certificate and communication protocols.")

			
			message = {
				'data': base64.b64encode(data),
				'iv': base64.b64encode(iv),
				'salt': base64.b64encode(salt),
				'hmac': base64.b64encode(self.add_hmac(data,key))		
			}


			logger.info("Sending POST Challenge")
			request = requests.post(f'{SERVER_URL}/api',json=message, headers=headers)
			response = json.loads(request.text)

			message, key, iv, salt, hmac = self.receive_message(response)

			if not self.verify_hmac(hmac,message,key):
				exit(0)
			else:
				logger.info("HMAC OK")
				message = self.decrypt_message(message,iv,key)
				message=json.loads(message)
				if message['method'] == 'ACK':
					self.state='ACCEPT_CHALLENGE'					
				else:
					logger.error(message['content'])
					return False
		else:
			return False
		

	def derive_key(self, data, salt=None):
		"""Derives key from a given data""" 
		digest=None
		if salt==None:
			salt=os.urandom(16)
		if self.digest == 'SHA-512':
			digest = hashes.SHA512()
		elif self.digest == 'SHA-256':
			digest =hashes.SHA256()

		key_size = 32
		if self.cipher=='3DES': 
			key_size = 16
		# derive
		kdf = PBKDF2HMAC(
			algorithm=digest,
			length=key_size*2	,
			salt=salt,
			iterations=10000,
		)
		key = kdf.derive(data)
		return key,salt

	def add_hmac(self, message, key):
		"""Calculates the hmac of a given message"""
		msg_bytes = None
		enc_shared_key = key[:len(key)//2]
		if self.digest == 'SHA-512':
			h = hmac.HMAC(enc_shared_key, hashes.SHA512())
			h.update(message)
			msg_bytes = h.finalize()
		elif self.digest == 'SHA-256':
			h = hmac.HMAC(enc_shared_key, hashes.SHA256())
			h.update(message)
			msg_bytes = h.finalize()
		return msg_bytes

	def verify_hmac(self, recv_hmac, crypto, key=None):
		"""Verifies the integrity of a message"""

		if key == None:
			key = self.shared_key
		h = None
		digest = None
		if self.digest == 'SHA-512':
			digest = hashes.SHA512()
		elif self.digest == 'SHA-256':
			digest = hashes.SHA256()
		#size = self.key_sizes[self.cipher][0]
		h = hmac.HMAC(key[:len(key)//2], digest)
		h.update(crypto)
		try:
			h.verify(recv_hmac)
			return True
		except:
			logger.error("HMAC Wrong. Communications will not continue")
			return False

	def get_list(self):
		if self.state=='ACCEPT_CHALLENGE':
			payload=None
			if self.session_id!=None:
				key, salt = self.derive_key(self.shared_key)
				data=json.dumps({'method': 'GET_LIST'}).encode('latin')
				data, iv = self.encrypt_message(data,key)
				headers = {
					'content':base64.b64encode(data),
					'iv':base64.b64encode(iv),
					'salt':base64.b64encode(salt),
					'session_id': str(self.session_id),
					'hmac':base64.b64encode(self.add_hmac(data,key))
				}


			logger.info("get list")

			req = requests.get(f'{SERVER_URL}/api',headers=headers)

			if req.status_code == 200:
				print("Got Server List")

			response = json.loads(req.text)
			message, key, iv, salt, hmac = self.receive_message(response)
			#message = base64.b64decode(data['message'])
			#iv = base64.b64decode(data['iv'])
			#salt = base64.b64decode(data['salt'])
			#key,_ = self.derive_key(self.shared_key,salt)
			#hmac = base64.b64decode(data['hmac'])

			logger.info("verifying hmac..")
			if self.verify_hmac(hmac, message,key):
				logger.info("HMAC OK")
				content=json.loads((self.decrypt_message(message, iv,key)))
				content=json.loads(content)
				if content['method']== 'ACK':
					media_list =content['media_list']
					self.state='SERVER_LIST'
					return media_list
				else:
					logger.info(content['content'])
					return False

			else:
				exit(0)
		else:
			return False

	def leave(self):
		key, salt = self.derive_key(self.shared_key)
		headers = {
		'Content-Type': 'application/json',
		'session_id': str(self.session_id)
		}

		message = json.dumps({'method': 'GOODBYE'}).encode('latin')
		data, iv = self.encrypt_message(message,key)
		message = {
			'data': base64.b64encode(data),
			'iv': base64.b64encode(iv),
			'salt': base64.b64encode(salt),
			'hmac': base64.b64encode(self.add_hmac(data,key))		
		}


		logger.info("Sending POST to Leave")
		request = requests.post(f'{SERVER_URL}/api',json=message, headers=headers)
		response = json.loads(request.text)
		message, key, iv, salt, hmac = self.receive_message(response)
		if self.verify_hmac(hmac, message,key):
			content=json.loads((self.decrypt_message(message, iv,key)))
			if content['method']== 'ACK':
					logger.info("goodbye")
					return 
			else:
				logger.error(content['content'])
			return		
		else:
			return




	def list_media_content(self,media_list):
		idx = 0
		print("MEDIA CATALOG\n")
		for item in media_list:
			print(f'{idx} - {media_list[idx]["name"]}')
		print("----")

		while True:
			selection = input("Select a media file number (q to quit): ")
			if selection.strip() == 'q':
				self.leave()
				sys.exit(0)

			if not selection.isdigit():
				continue

			selection = int(selection)
			if 0 <= selection < len(media_list):
				break

		# Example: Download first file
		media_item = media_list[selection]
		return media_item

	def get_new_license(self,media_id):
		if self.state=='SERVER_LIST':

			payload=None
			if self.session_id!=None:
				key, salt = self.derive_key(self.shared_key)
				message, iv = self.encrypt_message(json.dumps({'method': 'GET_LICENSE','media_id':media_id}).encode('latin'),key)
				headers = {
					'content':base64.b64encode(message),
					'iv':base64.b64encode(iv),
					'salt':base64.b64encode(salt),
					'session_id': str(self.session_id),
					'hmac':base64.b64encode(self.add_hmac(message,key))
				}
				req = requests.get(f'{SERVER_URL}/api',headers=headers)

				##response
				response = json.loads(req.text)
				message, key, iv, salt, hmac = self.receive_message(response)
				#salt = base64.b64decode(response['salt'])
				#key,_=self.derive_key(self.shared_key,salt)
				
				#iv =base64.b64decode(response['iv'])
				#hmac=base64.b64decode(response['hmac'])
				#msg = base64.b64decode(response['message'])
				if not self.verify_hmac(hmac,message,key):
					exit(0)
				else:
					message = json.loads(self.decrypt_message(message,iv,key))
					if message['method'] == 'ACK':
						license = message['license']
						logger.info("Got new License")
						self.licenses['media_id'] = x509.load_pem_x509_certificate(license.encode('latin'))
						return self.start_download(media_id)
					else:
						logger.error(message['content'])
						return False
		else:
			return False



	def start_download(self,media_id):
		if self.state == 'SERVER_LIST':
			license = self.licenses.get('media_id')
			if license == None:
				return self.get_new_license(media_id)
				
			license=license.public_bytes(serialization.Encoding.PEM).decode('latin')
			
			key, salt = self.derive_key(self.shared_key)
			
			headers = {
				'Content-Type': 'application/json',				
				'session_id': str(self.session_id)
			}
			
			data,iv = self.encrypt_message(json.dumps({
				'method': 'START_DOWNLOAD',
				'license':license,
				'media_id':media_id
			}).encode('latin'),key)
			
			message = {
				'data':base64.b64encode(data),
				'iv':base64.b64encode(iv),
				'salt':base64.b64encode(salt),
				'hmac':base64.b64encode(self.add_hmac(data,key))
			}

			logger.info("sending post to start download")
			req = requests.post(f'{SERVER_URL}/api',json=message,headers=headers)

			response = json.loads(req.text)

			message, key, iv, salt, hmac = self.receive_message(response)
			#iv =base64.b64decode(response['iv'])
			#hmac=base64.b64decode(response['hmac'])
			#salt = base64.b64decode(response['salt'])
			#msg = base64.b64decode(response['message'])
			
			#key, _ = self.derive_key(self.shared_key,salt)
			if not self.verify_hmac(hmac,message,key):
				exit(0)
			else:
				message = json.loads(self.decrypt_message(message,iv,key))
				method = message['method']
				if method == 'ACK':
					logger.info("Server validated the license")
					self.state = 'START_DOWNLOAD'
					return True
				else:
					logger.error(message['content'])		
					return False
		else:
			return False


def main():
	print("|--------------------------------------|")
	print("|         SECURE MEDIA CLIENT          |")
	print("|--------------------------------------|\n")

	# Get a list of media files
	print("Contacting Server")

	# TODO: Secure the session
	client = Client()

	if not client.has_negotiated():
		client.negotiate_algs()
		client.dh_start()
		client.dh_exchange_key()
		client.start_challenge()
	# client.send_message('')

	# client or server sends the algorithms to be used and the other sends the response (encoded with public?)

	# client generates simetric key and sends it encrypted with server public key

	# validate all messages with MAC (calculate hash negotiated from last step and prepend it in the end)
	media_list=None
	if client.shared_key!=None:
		media_list=client.get_list()
		#print(media_list)
	
	#media_list = req.json()
	media_item=None
	if media_list != None:
		media_item=client.list_media_content(media_list)
		#print(media_item)
	# Present a simple selection menu

	
	headers={
		'session_id': str(client.session_id)
	}

	if not client.start_download(media_item['id']):
		return 
	
	print(f"Playing {media_item['name']}")

	# Detect if we are running on Windows or Linux
	# You need to have ffplay or ffplay.exe in the current folder
	# In alternative, provide the full path to the executable
	if os.name == 'nt':
		proc = subprocess.Popen(
			['ffplay.exe', '-i', '-'], stdin=subprocess.PIPE)
	else:
		proc = subprocess.Popen(['ffplay', '-i', '-'], stdin=subprocess.PIPE)


	for chunk in range(media_item['chunks'] + 1):
		payload=None
		if client.session_id!=None:
			key1, salt1 = client.derive_key(client.shared_key)
			message, iv = client.encrypt_message(json.dumps({'method': 'DOWNLOAD','chunk_id':chunk,'media_id':media_item['id']}).encode('latin'),key1)
			headers = {
				'content':base64.b64encode(message),
				'iv':base64.b64encode(iv),
				'salt':base64.b64encode(salt1),
				'session_id': str(client.session_id),
				'hmac':base64.b64encode(client.add_hmac(message,key1))
			}

		req = requests.get(f'{SERVER_URL}/api',headers=headers)
		response = json.loads(req.text)
		
		
		
		iv = base64.b64decode(response['iv'])
		hmac = base64.b64decode(response['hmac'])
		salt = base64.b64decode(response['salt'])
		msg = base64.b64decode(response['message'])
		key, _ = client.derive_key(client.chunk_identification(chunk,media_item['id']), salt)

		if client.verify_hmac(hmac, msg, key):
			logger.info("HMAC OK")
			data = json.loads(client.decrypt_message(msg, iv, key))
			if data['method'] == 'ACK':
				data = binascii.a2b_base64(data['chunk_data'])
				try:
					proc.stdin.write(data)
				except:
					break
			else :
				logger.error(data['content'])
		else:
			logger.error("HMAC Wrong. Communications compromised")
			exit(0)


if __name__ == '__main__':

	while True:
		main()
		time.sleep(1)
