#!/usr/bin/env python

from twisted.web import server, resource
from twisted.internet import reactor, defer
from cryptography.hazmat.backends.interfaces import RSABackend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as pd
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.hazmat.primitives import serialization  
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import logging
import binascii
import json
import os
import math
import base64
from cryptography.hazmat.primitives import hashes, hmac
from cryptography import x509 
from datetime import datetime,timedelta
from cryptography.x509.oid import NameOID
import sys

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

CATALOG = { '898a08080d1840793122b7e118b27a95d117ebce': 
			{
				'name': 'Sunny Afternoon - Upbeat Ukulele Background Music',
				'album': 'Upbeat Ukulele Background Music',
				'description': 'Nicolai Heidlas Music: http://soundcloud.com/nicolai-heidlas',
				'duration': 3*60+32,
				'file_name': '898a08080d1840793122b7e118b27a95d117ebce.mp3',
				'file_size': 3407202
			}
		}

CATALOG_BASE = 'catalog'
CHUNK_SIZE = 1024 * 4
ENC_SALT = b'\xb5\x0e\x96\x14\x8f\xbb#`~\xc0\xfd&\xd2\xd6\x8cy'
ENC_IV = b'\xb6X_\xe4t1\x10\x0e\x07o"\xd6\xe8\x8d\x1cd'


class Session:

	counter = 0
	def __init__(self):
		self.id = Session.counter
		self.pub_key = None				# public key do server
		self.priv_key = None			# private key do server
		self.client_pub_key = None 		# public key do cliente
		self.shared_key = None			# shared key
		self.cipher = None				
		self.mode = None
		self.digest = None
		self.dh_parameters = None
		self.user = None
		self.state='INITIAL'
		Session.counter+=1


	
class MediaServer(resource.Resource):
	isLeaf = True
	def __init__(self):
		
		self.ciphers = ['AES','3DES','ChaCha20']
		self.digests = ['SHA-512','SHA-256','SHA-384']
		self.ciphermodes = ['CBC','CTR']
		self.sessions={}
		self.certificate = self.load_cert('../Certs/sio_server.crt')
		self.load_priv_key('../Certs/sio_server.pem')
		self.files = {}  #the catalog
		#self.encrypt_catalog('./catalog/')
		self.decrypt_catalog('./catalog/')
		self.licenses = {}		# media_id : list(user)	




	def encrypt_catalog(self,path):
		kdf = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=32,
			salt=ENC_SALT,
			iterations=10000,
		)
		key=kdf.derive(b"password")
		key=key[:16]
		self.catalog_algorithm=algorithm=algorithms.AES(key[:16])
		iv=ENC_IV
		self.catalog_cipher = Cipher(algorithm, modes.CBC(iv))
		encryptor = self.catalog_cipher.encryptor()
		with os.scandir(path) as it:
			for entry in list(it):
				if entry.is_file() and entry.name.endswith('.mp3'):
					with open(path + entry.name,'rb') as f:
						data=f.read()
						padder = padding.PKCS7(algorithm.block_size).padder()
						padded_data = padder.update(data)
						padded_data += padder.finalize()
						cryptogram = encryptor.update(padded_data) + encryptor.finalize()
					with open(path + entry.name, 'wb') as outputfile:
						outputfile.write(cryptogram)

						
		#self.decrypt_catalog(path,'898a08080d1840793122b7e118b27a95d117ebce')							
	def decrypt_catalog(self,path):
		kdf = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=32,
			salt=ENC_SALT,
			iterations=10000,
		)
		key=kdf.derive(b"password")
		key=key[:16]
		algorithm=algorithms.AES(key[:16])
		iv=ENC_IV
		cypher = Cipher(algorithm, modes.CBC(iv))
		decryptor=cypher.decryptor()
		with os.scandir(path) as it:
			for entry in list(it):
				if entry.is_file() and entry.name.endswith('.mp3'):
					with open(path + entry.name,'rb') as f:
						cryptogram=f.read()
						padded_data = decryptor.update(cryptogram) + decryptor.finalize()
						unpadder = padding.PKCS7(algorithm.block_size).unpadder()
						text = unpadder.update(padded_data)	
						text += unpadder.finalize()
						self.files[entry.name[:-4]] = text


	def choose_alg(self,ciphers,digests,modes):
		
		availableciphers=[c for c in self.ciphers if c in ciphers]
		availabledigests=[c for c in  self.digests if c in digests]
		availablemodes=[c for c in self.ciphermodes if c in modes]
		if len(availableciphers)==0 or len(availabledigests) == 0  or (len(availablemodes) == 0 and 'ChaCha20' not in availableciphers):
			return None,None,None
		cipher = availableciphers[0]
		digest=availabledigests[0]
		mode=None
		
		if cipher!='ChaCha20':
			mode = availablemodes[0] 
			if cipher == '3DES':
				mode=[md for md in availablemodes if md != 'CTR'][0]
			else:
				mode=availablemodes[0]

		return cipher,digest,mode

	def negotiate_alg(self,data):
		logger.debug('CHECKING CIPHERS')
		client_ciphers,client_digests,client_ciphermodes=data['ciphers'],data['digests'],data['ciphermodes']
		cipher, digest, mode = self.choose_alg(client_ciphers,client_digests,client_ciphermodes)

		if cipher == None or digest == None or mode == None:
			logger.error('NO AVAILABLE CIPHERS,DIGESTS OR CIPHERMODES')
			data={'method': 'NACK','content':'The server does not have any of the client\'s cihpers,digests  or ciphermodes'}
			return json.dumps(data).encode('latin')
	
		# enviar mensagem a dizer q n pode
		#server chooses the cipher to communicate acordding to client's available ciphers
		session = Session()

		session.cipher = cipher
		session.digest = digest
		session.mode = mode


		self.sessions[session.id] = session
		logger.debug('Success checking ciphers')
		#enviar 
		session.state='NEGOTIATE_ALGS' #this variable corresponds to the last state this session has been .
		message = {
			'method': 'ACK',
			'id':session.id,
			'cipher':session.cipher,
			'mode':session.mode,
			'digest':session.digest,
			'cert' : base64.b64encode(self.certificate.public_bytes(serialization.Encoding.PEM)).decode('latin')
			}

		message = json.dumps(message).encode('latin')
		return message

	def check_session_id(self,args):
		if b'session_id' not in args:
			logger.debug("id not in the request parameters")
			return None
		logger.debug("id is in the request parameters")
		id = int(args[b'session_id'].decode())
		session = self.sessions.get(id)
		logger.debug(session.id)
		if session == None:
			return None
		return session

	def load_cert(self,_file):
		try:

			with open(_file, 'rb') as f:
				cert = x509.load_pem_x509_certificate(f.read())
		except:
			logger.debug("Could not read server certificate.Make sure to run this file on the /server directory")
			exit(0)
		return cert
	
	def validate_certificate(self,certificate):
		dates = (certificate.not_valid_before.timestamp(),certificate.not_valid_after.timestamp())
		date_now=datetime.now().timestamp()
		return dates[0]< date_now < dates[1]


	def load_priv_key(self,_file):
		try:
			with open(_file,'rb') as f:
				self.private_key = serialization.load_pem_private_key(f.read(),password=None)
		except:
			logger.debug("Could not Load Private key. Make sure to run this file on the /server directory")
			exit(0)
		
	def sign_message(self,msg):
		signature = self.private_key.sign(
			msg,
			pd.PSS(mgf=pd.MGF1(hashes.SHA256()), salt_length=pd.PSS.MAX_LENGTH), 
			hashes.SHA256()
		)
		signature = bytes(signature)
		return signature
		

	def verify_license_signature(self,license):
		try:
			self.certificate.public_key().verify(
				license.signature,
				license.tbs_certificate_bytes,
				pd.PKCS1v15(),
				license.signature_hash_algorithm,
			)
			logger.debug("License Signature OK")
			return True
		except:
			logger.debug("License Signature Wrong")
			return False
	
	def validate_license(self,license,media_id):
		""" Checks if license is up to date and if it is equal to the server,
			and if the signature is valid
		"""
		now = datetime.now().timestamp()
		dates = (license.not_valid_before.timestamp(),license.not_valid_after.timestamp())
		return ( dates[0] < now < dates[1] and license in self.licenses[(media_id).decode('latin')]  and 
		any(license.subject.rfc4514_string() == lc.subject.rfc4514_string() for lc in self.licenses[(media_id).decode('latin')])
		and  self.verify_license_signature(license)
		)


	def gen_license(self,session,media_id):
		
		subject = x509.Name([
		x509.NameAttribute(NameOID.COUNTRY_NAME, u"PT"),
		x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Aveiro"),
		x509.NameAttribute(NameOID.LOCALITY_NAME, u"Aveiro"),
		x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"DETI"),
		x509.NameAttribute(NameOID.COMMON_NAME, str(session.user)),
		])
		cert = x509.CertificateBuilder().subject_name(
			subject
		).issuer_name(
			self.certificate.subject
		).public_key(
			self.certificate.public_key()
		).serial_number(
			x509.random_serial_number()
		).not_valid_before(
			datetime.utcnow()
		).not_valid_after(
			datetime.utcnow() + timedelta(days=10)
		).sign(self.private_key, hashes.SHA256())
		if media_id not in self.licenses:
			self.licenses[media_id]=set()
			self.licenses[media_id].add(cert)
		else:
			self.licenses[media_id].add(cert)
	
		return cert
		



	def do_download(self,request,session,media_id,chunk_id):
		
		request.responseHeaders.addRawHeader(b"content-type", b"application/json")
		key,salt=self.derive_key(self.chunk_identification(session,chunk_id,media_id),session)
		# Search media_id in the catalog
		if media_id not in CATALOG:
			request.setResponseCode(404)
			request.responseHeaders.addRawHeader(b"content-type", b"application/json")
			data=json.dumps({'method':'NACK','content':'media file not found'}).encode('latin')
			data,iv=self.encrypt_message(data,session,key)
			response = json.dumps({
			'message': base64.b64encode(data).decode('latin'),
			'iv': base64.b64encode(iv).decode('latin'),
			'salt': base64.b64encode(salt).decode('latin'),
			'hmac': base64.b64encode(self.add_hmac(data,session,key)).decode('latin')})
			return response.encode('latin')
		
		# Get the media item
		media_item = CATALOG[media_id]

		# Check if a chunk is valid
		#chunk_id = request.args.get(b'chunk', [b'0'])[0]
		valid_chunk = False
		try:
			chunk_id = int(chunk_id)
			if chunk_id >= 0 and chunk_id  < math.ceil(media_item['file_size'] / CHUNK_SIZE):
				valid_chunk = True
		except:
			logger.warn("Chunk format is invalid")

		if not valid_chunk:
			request.setResponseCode(400)
			request.responseHeaders.addRawHeader(b"content-type", b"application/json")
			data=json.dumps({'method':'NACK','content':'chunk id not found'}).encode('latin')
			data,iv=self.encrypt_message(data,session,key)
			response = json.dumps({
			'message': base64.b64encode(data).decode('latin'),
			'iv': base64.b64encode(iv).decode('latin'),
			'salt': base64.b64encode(salt).decode('latin'),
			'hmac': base64.b64encode(self.add_hmac(data,session,key)).decode('latin')})
			return response.encode('latin')
			
		logger.debug(f'Download: chunk: {chunk_id}')

		offset = chunk_id * CHUNK_SIZE

		
		# Open file, seek to correct position and return the chunk
		chunk_data=self.files[media_id]
		chunk_data=chunk_data[offset:offset+CHUNK_SIZE]
		data=json.dumps({'method':'ACK',
					'chunk_data': binascii.b2a_base64(chunk_data).decode('latin').strip(),}).encode('latin')

		data,iv=self.encrypt_message(data,session,key)
		#binascii.b2a_base64(data).decode('latin').strip(),
		return json.dumps(
				{	
					'message': base64.b64encode(data).decode('latin'),
					'iv': base64.b64encode(iv).decode('latin'),
					'salt': base64.b64encode(salt).decode('latin'),
					'hmac': base64.b64encode(self.add_hmac(data,session,key)).decode('latin')
				},indent=4	
			).encode('latin')

		# File was not open?
		request.responseHeaders.addRawHeader(b"content-type", b"application/json")
		return json.dumps({'error': 'unknown'}, indent=4).encode('latin')


	def verify_hmac(self,session, recv_hmac, crypto, key):
		h = None
		digest = None
		if session.digest == 'SHA-512':
			digest = hashes.SHA512()
		elif session.digest == 'SHA-256':
			digest = hashes.SHA256()
		h = hmac.HMAC(key[:len(key)//2], digest)
		h.update(crypto)
		try:
			h.verify(recv_hmac)
			return True
		except:
			logger.info("HMAC Wrong. Communications will not continue")
			return False


	def encrypt_message(self,text,session,key):

		cipher=None
		algorithm,iv=None,None
		mode=None
		enc_shared_key=key[len(key)//2:]
		if session.cipher == 'AES':
			algorithm = algorithms.AES(enc_shared_key)

		elif session.cipher == '3DES':
			algorithm = algorithms.TripleDES(enc_shared_key)
		elif session.cipher == 'ChaCha20':
			iv = os.urandom(16)
			algorithm = algorithms.ChaCha20(enc_shared_key,iv)
		else:
			logger.debug('Algorithm not suported')
		if session.cipher != 'ChaCha20':
			#with ChaCha20 we do not pad the data
			iv = os.urandom(algorithm.block_size // 8)
			
			if session.mode == 'CBC':
				mode = modes.CBC(iv)
			elif session.mode == 'CTR':
				mode = modes.CTR(iv)
			padder = padding.PKCS7(algorithm.block_size).padder()
			padded_data = padder.update(text)
			padded_data += padder.finalize()
			text=padded_data
					
		cipher = Cipher(algorithm, mode=mode)  
		encryptor = cipher.encryptor()
		cryptogram = encryptor.update(text) + encryptor.finalize()
		return cryptogram, iv

	def add_hmac(self,message,session,key):

		msg_bytes=None
		enc_shared_key = key[:len(key)//2]
		if session.digest == 'SHA-512':
			h = hmac.HMAC(enc_shared_key, hashes.SHA512())
			h.update(message)
			msg_bytes = h.finalize() 
		elif session.digest == 'SHA-256':
			h = hmac.HMAC(enc_shared_key, hashes.SHA256())
			h.update(message)
			msg_bytes = h.finalize() 
		return msg_bytes


	def decrypt_message(self,cryptogram,iv,session,key):
		cipher=None
		algorithm=None
		mode=None
		enc_shared_key = key[len(key)//2:]

		if session.cipher == 'AES':
			algorithm = algorithms.AES(enc_shared_key)
		elif session.cipher == '3DES':
			algorithm = algorithms.TripleDES(enc_shared_key)
		elif session.cipher == 'ChaCha20':
			if iv!=None:
				algorithm = algorithms.ChaCha20(enc_shared_key,iv)
		else:
			logger.debug('Algorithm not suported')

		#with ChaCha20 we do not pad the data
		if session.mode == 'CBC':
			mode = modes.CBC(iv)
		elif session.mode == 'CTR':
			mode = modes.CTR(iv)
		elif session.mode == 'ECB':
			mode =modes.ECB(iv)
		cipher = Cipher(algorithm, mode=mode)       

		decryptor = cipher.decryptor()
		if session.cipher == 'ChaCha20': 
			return decryptor.update(cryptogram) + decryptor.finalize()
		else:
			padded_data = decryptor.update(cryptogram) + decryptor.finalize()
			unpadder = padding.PKCS7(algorithm.block_size).unpadder()
			text = unpadder.update(padded_data)	
			text += unpadder.finalize()
			return text


	def chunk_identification(self, session,chunk_id, media_id):
		media_id=media_id
		chunk_id=str(chunk_id)
		final_id=(session.shared_key.decode('latin')+media_id+chunk_id).encode('latin')
		return final_id

	def derive_key(self, data,session,salt=None):
		digest=None
		if session.digest == 'SHA-512':
			digest = hashes.SHA512()
		elif session.digest == 'SHA-256':
			digest =hashes.SHA256()
		
		if salt == None:
			salt = os.urandom(16)
		
		# derive
		key_size = 32
		if session.cipher == '3DES': 
			key_size = 16
			
		kdf = PBKDF2HMAC(
			algorithm=digest,
			length=key_size*2,
			salt=salt,
			iterations=10000,
		)
		key = kdf.derive(data)
		return key,salt


	
	def dh_key_gen(self,request):
		"""
		Generates the parameters necessary to start the Diffie-Hellman Algorithm
		along with the server private and public key.
		After that sends to client parameters and pub_key
		"""
		logger.debug('Generating parameters and keys...')

		session = self.check_session_id(request.getAllHeaders())
		if session == None:
			return json.dumps({ 'method':'NACK','content': 'Session ID not found or not passed'}, indent=4).encode('latin')

		if session.state != 'NEGOTIATE_ALGS':
			return json.dumps({ 'method':'NACK','content': 'Could not Generate keys and parameters. Invalid current state'},
			indent=4).encode('latin')
		
		session.dh_parameters = dh.generate_parameters(generator=2, key_size=1024)
		session.private_key = session.dh_parameters.generate_private_key()
		session.public_key = session.private_key.public_key()
		parameter_num = session.dh_parameters.parameter_numbers()
		logger.debug('Generated keys and parameters with sucess')

		pub_key=session.public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
		skey = self.sign_message(pub_key) 
		data = {'method':'ACK',
			'p':parameter_num.p,
			'g':parameter_num.g,
			'pub_key':pub_key.decode(),
			'signature':skey.decode('latin')
		}	
		session.state='DH_START'
		message = json.dumps(data).encode('latin')	
		return message
	
	def dh_exchange_key(self,request):
		data= json.loads(request.content.getvalue())
		session = self.check_session_id(request.getAllHeaders())
		if session == None:
			return json.dumps({ 'method':'NACK','content': 'Session ID not found or not passed'}, indent=4).encode('latin')

		if session.state != 'DH_START':
			logger.debug('Could not exchange a key.')
			return json.dumps({'method': 'NACK','content':'Could not exchange a key.'}).encode('latin')
		method=data['method']
		
		if method =='KEY_EXCHANGE':
			logger.debug('Confirmed the exchange of a key')
			received_key=data['pub_key'].encode()
			#received_key = self.sign_message(received_key)
			logger.debug(received_key)
			session.client_pub_key=load_pem_public_key(received_key)
			session.shared_key = session.private_key.exchange(session.client_pub_key)
			session.state='KEY_EXCHANGE'
			message = {'method':'ACK'}
			return json.dumps(message).encode('latin')

		return json.dumps(message).encode('latin')
		
		
	def accept_challenge(self,request,session,data):
		
		nonce = data['nonce'].encode('latin')
		client_cert = data['cert'].encode('latin')
		session.cert = x509.load_pem_x509_certificate(client_cert)
		logger.debug("Got Nonce and Client Certificate. Validating Certificate..")
		message=None
		if session.state !='KEY_EXCHANGE':
			message=json.dumps({'method': 'NACK','content':'Could not Accept challenge. Invalid State'}).encode('latin')
		elif not self.validate_certificate(session.cert):
			logger.debug("Client certificate is not valid!")
			message=json.dumps({'method': 'NACK','content':'Client Certificate is not valid'}).encode('latin')
		else:
			snonce = self.sign_message(nonce)
			nonce2=os.urandom(16)
			session.nonce2 = nonce2
			
			message=json.dumps({
				'method' : 'ACK',
				'snonce':snonce.decode('latin'),
				'nonce2':nonce2.decode('latin')
			}).encode('latin')
		
		key, salt = self.derive_key(session.shared_key,session)
		message,iv = self.encrypt_message(message,session,key)
		session.state='ACCEPT_CHALLENGE'
		message = json.dumps({
			'message':base64.b64encode(message).decode('latin'),
			'iv':base64.b64encode(iv).decode('latin'),
			'salt':base64.b64encode(salt).decode('latin'),
			'hmac':base64.b64encode(self.add_hmac(message,session,key)).decode('latin')
			})
		return message.encode('latin')

	def verify_challenge(self,request,session,data):
		logger.debug("Verifing Challenge")
		nonce2 = data['snonce2'].encode('latin')
		message=None
		key, salt = self.derive_key(session.shared_key,session)
		message=None
		if session.state != 'ACCEPT_CHALLENGE':
			message=json.dumps({
					'method':'NACK',
					'content':'Could not Verify Challenge. Invalid State.'
				}).encode('latin')

		else:
			try:
				session.cert.public_key().verify(nonce2,session.nonce2, pd.PKCS1v15(), hashes.SHA1()) 
				logger.debug("Challenge OK")
				protocols = json.loads(data['protocols'])
				
				ccipher, cdigest, cmode = self.choose_alg(protocols['cipher'],protocols['digest'],protocols['mode'])

				if session.cipher != ccipher or session.digest != cdigest or session.mode != cmode:
					message=json.dumps({'method':'NACK','content':'The Choosen Algorithms were downgraded'}).encode('latin')
				else:
					message=json.dumps({
						'method':'ACK' 
					}).encode('latin')
					session.state='VERIFY_CHALLENGE'
					cc_num=session.cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
					session.user = str(cc_num[0].value) 
			except:
				logger.debug("Challenge Wrong")
				message=json.dumps({
					'method':'NACK',
					'content':'Challenge Wrong'
				}).encode('latin')

		

		message,iv = self.encrypt_message(message,session,key)
		response = json.dumps({
			'message':base64.b64encode(message).decode('latin'),
			'iv':base64.b64encode(iv).decode('latin'),
			'salt':base64.b64encode(salt).decode('latin'),
			'hmac':base64.b64encode(self.add_hmac(message,session,key)).decode('latin')
		}).encode('latin')	
		return response			
		# Send the list of media files to clients
	def do_list(self, request,session):

		# Build list
		message=None
		if session.state!='VERIFY_CHALLENGE':
			data = {'method':'NACK','content': 'Could not get the List of Media Content. Invalid State'}
		else:
			media_list = []
			for media_id in CATALOG:
				media = CATALOG[media_id]
				media_list.append({
					'id': media_id,
					'name': media['name'],
					'description': media['description'],
					'chunks': math.ceil(media['file_size'] / CHUNK_SIZE),
					'duration': media['duration']
					})
			#print(type(media_list[0]['id']))
			# Return list to client
			
			logger.debug(request.args)
			#params=j
			session.state='SERVER_LIST'
			data=json.dumps({'method':'ACK', 'media_list':media_list})

		key,salt = self.derive_key(session.shared_key,session)
		cryptogram,iv=self.encrypt_message(json.dumps(data).encode('latin'),session,key)
		hmac=self.add_hmac(cryptogram,session,key)
		#print(type(cryptogram.decode('latin')))
		data = base64.b64encode(cryptogram).decode('latin')
		iv = base64.b64encode(iv).decode('latin')
		salt=base64.b64encode(salt).decode('latin')
		hmac=base64.b64encode(hmac).decode('latin')
		response= {'message':data,'iv':iv,'salt':salt ,'hmac': hmac}
		return json.dumps(response, indent=4).encode('latin')

	def send_license(self,session,media_id):
		#licenses = self.licenses[media_id]
		key, salt = self.derive_key(session.shared_key,session)
		data,iv=None,None
		if session.state == 'SERVER_LIST':
			if media_id in self.licenses and any(license.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == session.user for license in self.licenses[media_id]):
					data,iv = self.encrypt_message(json.dumps({
					'method':'NACK',
					'content':'Cannot Obtain license. Client already has one'}).encode('latin'),session,key);
			else:
				cert = self.gen_license(session,media_id)
				data,iv = self.encrypt_message(json.dumps({
					'method':'ACK',
					'license':cert.public_bytes(serialization.Encoding.PEM).decode('latin')}).encode('latin'),session,key)
		else:
			data,iv = self.encrypt_message(json.dumps({
				'method':'NACK',
				'content':'Cannot Obtain license. Invalid State'}).encode('latin'),session,key);

		response=json.dumps({
			'message':base64.b64encode(data).decode('latin'),
			'iv':base64.b64encode(iv).decode('latin'),
			'salt':base64.b64encode(salt).decode('latin'),
			'hmac':base64.b64encode(self.add_hmac(data,session,key)).decode('latin'),
		})
		logger.debug("Sent license")
		return response.encode('latin')
		
	def start_download(self,request,session,data):
		message=None
		if session.state!='SERVER_LIST':
			message=json.dumps({
					'method':'NACK',
					'content':'Could not Start Download. Invalid State.'
				}).encode('latin')
		else:
			license=data['license'].encode('latin')
			media_id = data['media_id'].encode('latin')
			key, salt = self.derive_key(session.shared_key,session)
			license = x509.load_pem_x509_certificate(license)
			if self.validate_license(license,media_id):
				session.state='START_DOWNLOAD'
				message=json.dumps({'method':'ACK'}).encode('latin')
			else:
				message=json.dumps({'method':'NACK','content':'License not Valid'}).encode('latin')
				


			content,iv=self.encrypt_message(json.dumps({'method':'ACK'}).encode('latin'),session,key)
			response=json.dumps({
					'message':base64.b64encode(content).decode('latin'),
					'iv':base64.b64encode(iv).decode('latin'),
					'salt':base64.b64encode(salt).decode('latin'),
					'hmac':base64.b64encode(self.add_hmac(content,session,key)).decode('latin')
					})
		return response.encode('latin')
		



	def clean_session(self,session):
		if session.id in self.sessions:
			del self.sessions[session.id]
			return True
		else:
			return False
		
	def leave(self,request,session):
		key, salt = self.derive_key(session.shared_key,session)
		message=None
		if self.clean_session(session):
			logger.debug("Cleared Session")
			message=json.dumps({ 'method':'ACK'}).encode('latin')
		else:
			logger.debug("Session id not Found")
			message=json.dumps({ 'method':'NACK','content': 'Session id not Found'}).encode('latin')
		key, salt = self.derive_key(session.shared_key,session)
		message,iv = self.encrypt_message(message,session,key)
		response = json.dumps({
			'message':base64.b64encode(message).decode('latin'),
			'iv':base64.b64encode(iv).decode('latin'),
			'salt':base64.b64encode(salt).decode('latin'),
			'hmac':base64.b64encode(self.add_hmac(message,session,key)).decode('latin')
			}).encode('latin')
		return response

	def hmac_wrong_message(self,session):
		key,salt=self.derive_key(session.shared_key,session)
		
		message=json.dumps({
				'method':'NACK',
				'content':'HMAC Wrong!'
			}).encode('latin')

		message,iv = self.encrypt_message(message,session,key)
		response = json.dumps({
			'message':base64.b64encode(message).decode('latin'),
			'iv':base64.b64encode(iv).decode('latin'),
			'salt':base64.b64encode(salt).decode('latin'),
			'hmac':base64.b64encode(self.add_hmac(message,session,key)).decode('latin')
		}).encode('latin')	
		return response


	# Handle a GET request
	def render_GET(self, request):
		logger.debug(f'Received request for {request.uri}')
		print(request.uri)

		try:
			if request.path == b'/api/protocols':
				return self.do_get_protocols(request)
			elif request.path == b'/api/key':
				request.responseHeaders.addRawHeader(b"content-type", b"application/json")
				logger.debug("entrei")
				return self.dh_key_gen(request)
			elif request.uri == b'/api':
				data = request.getAllHeaders()
				session=self.check_session_id(data)
				iv = base64.b64decode(data[b'iv'].decode())
				salt=base64.b64decode(data[b'salt'].decode())
				content = base64.b64decode(data[b'content'].decode())
				hmac = base64.b64decode(data[b'hmac'].decode())
				key,_=self.derive_key(session.shared_key,session,salt)			
				if not self.verify_hmac(session,hmac,content,key):
					logger.debug("HMAC WRONG")
					return self.hmac_wrong_message(session)

				
				data = self.decrypt_message(content,iv,session,key).decode('latin')
				data = json.loads(data.encode())
				method = data.get('method')
				
				if method == 'GET_LIST':
					return self.do_list(request,session)
				elif method == 'DOWNLOAD':
					chunk_id = data.get('chunk_id')
					media_id = data.get('media_id')
					#if media_id is None:
						#request.setResponseCode(400)
						#request.responseHeaders.addRawHeader(b"content-type", b"application/json")
						#return json.dumps({'error': 'invalid media id'}).encode('latin')
					return self.do_download(request,session,media_id,int(chunk_id))
				elif method == 'GET_LICENSE':
					media_id = data.get('media_id')
					return self.send_license(session,media_id)

		except Exception as e:
			logger.exception(e)
			request.setResponseCode(500)
			request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
			return b''
	


	# Handle a POST request
	def render_POST(self, request):
		logger.debug(f'Received POST for {request.uri}')
		try:
			if request.uri == b'/api/protocols':
				data = json.loads(request.content.getvalue())
				method=data['method']
				if method == 'NEGOTIATE_ALG':
					return self.negotiate_alg(data)
				elif method == 'KEY_EXCHANGE':
					return self.key_exchange(data)
			elif request.uri == b'/api/key':
				return self.dh_exchange_key(request)
			elif request.uri == b'/api':
				#read headers content
				headers = request.getAllHeaders()
				session=self.check_session_id(headers)
				
				body = json.loads(request.content.getvalue())
				iv=base64.b64decode(body['iv'])
				salt=base64.b64decode(body['salt'])
				hmac=base64.b64decode(body['hmac'])
				data = base64.b64decode(body['data'])
				
				key,_=self.derive_key(session.shared_key,session,salt)

				if not self.verify_hmac(session,hmac,data,key):
					return self.hmac_wrong_message(session)
				else:

					data = self.decrypt_message(data,iv,session,key).decode('latin')
					data = json.loads(data.encode())

					method = data.get('method')
					if method == 'START_CHALLENGE':
						logger.debug("START CHALLENGE")
						return self.accept_challenge(request,session,data)
					elif method == 'ACCEPT_CHALLENGE':
						logger.debug("ACCEPT CHALLENGE")
						return self.verify_challenge(request,session,data)
					elif method == 'START_DOWNLOAD':
						logger.debug("START DOWNLOAD")
						return self.start_download(request,session,data)
					elif method == 'GOODBYE':
						return self.leave(request,session)

		except Exception as e:
			logger.exception(e)
			request.setResponseCode(500)
			request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
			return b''

		return b''




print("Server started")
print("URL is: http://IP:8080")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()    
