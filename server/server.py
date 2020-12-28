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
				'file_size': 7072823
			}
		}

CATALOG_BASE = 'catalog'
CHUNK_SIZE = 1024 * 4

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

		Session.counter+=1


	
class MediaServer(resource.Resource):
	isLeaf = True
	def __init__(self):
		self.ciphers = ['AES','3DES','ChaCha20']
		self.digests = ['SHA-512','SHA-256','SHA-384']
		self.ciphermodes = ['CBC','CTR']
		self.key_sizes = {'3DES':[192,168,64],'AES':[256,192,128],'ChaCha20':[256]}
		self.sessions={}
		self.certificate = self.load_cert('../lixo/sio_server.crt')
		self.load_priv_key('../lixo/sio_server.pem')
		self.encrypt_catalog('./catalog')
		self.licenses = {}		# media_id : list(user)	


	def encrypt_catalog(self,path):
		kdf = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=32,
			salt=None,
			iterations=10000,
		)
		key=kdf.derive(b"password")
		key=key[:16]
		algorithm=algorithms.AES(key[:16])
		iv=os.urandom(16)
		mode= modes.CBC(iv)
		try:
			with os.scandir(path) as it:
				for entry in it:
					if entry.is_file():
						with open(path + entry.name,'rb') as f:
							data=f.read()
							padder = padding.PKCS7(algorithm.block_size).padder()
							padded_data = padder.update(data)
							padded_data += padder.finalize()
							cipher = Cipher(algorithm, mode=mode)  
							encryptor = cipher.encryptor()
							cryptogram = encryptor.update(padded_data) + encryptor.finalize()
							






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
		with open(_file, 'rb') as f:
			cert = x509.load_pem_x509_certificate(f.read())
		return cert
	
	def validate_certificate(self,certificate):
		dates = (certificate.not_valid_before.timestamp(),certificate.not_valid_after.timestamp())
		date_now=datetime.now().timestamp()
		return dates[0]< date_now < dates[1]


	def load_priv_key(self,_file):
		with open(_file,'rb') as f:
			self.private_key = serialization.load_pem_private_key(f.read(),password=None)
		

	def sign_message(self,msg):
		print(msg)
		signature = self.private_key.sign(
			msg,
			pd.PSS(mgf=pd.MGF1(hashes.SHA256()), salt_length=pd.PSS.MAX_LENGTH), 
			hashes.SHA256()
		)
		signature = bytes(signature)
		print(signature)
		return signature

	
	def validate_license(self,license,media_id):
		""" Checks if license is up to date and if it is equal to the server """
		now = datetime.now().timestamp()
		dates = (license.not_valid_before.timestamp(),license.not_valid_after.timestamp())
		print(self.licenses)
		return ( dates[0] < now < dates[1] and license in self.licenses[(media_id).decode('latin')]  and 
		any(license.subject.rfc4514_string() == lc.subject.rfc4514_string() for lc in self.licenses[(media_id).decode('latin')]))


	def gen_license(self,session,media_id):
		# Provide various details about who we are.
		subject = issuer = x509.Name([
		x509.NameAttribute(NameOID.COUNTRY_NAME, u"PT"),
		x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Aveiro"),
		x509.NameAttribute(NameOID.LOCALITY_NAME, u"Aveiro"),
		x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"DETI"),
		x509.NameAttribute(NameOID.COMMON_NAME, str(session.user)),
		])
		cert = x509.CertificateBuilder().subject_name(
			subject
		).issuer_name(
			issuer
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
			print(media_id)
			self.licenses[media_id]=set()
			self.licenses[media_id].add(cert)
		else:
			self.licenses[media_id].add(cert)
	
		return cert
		

	# Send the list of media files to clients
	def do_list(self, request,session):

		# Build list
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
		
		request.responseHeaders.addRawHeader(b"content-type", b"application/json")
		cryptogram,iv=self.encrypt_message(json.dumps(media_list).encode('latin'),session)
		hmac=self.add_hmac(cryptogram,session)
		logger.debug("teste")
		#print(type(cryptogram.decode('latin')))
		crypto = base64.b64encode(cryptogram).decode('latin')
		iv = base64.b64encode(iv).decode('latin')
		hmac=base64.b64encode(hmac).decode('latin')
		data= {'method':'SERVERLIST','cryptogram':crypto,'iv':iv, 'hmac': hmac}
		return json.dumps(data, indent=4).encode('latin')

	def do_download(self,request,session,media_id,chunk_id):
		
		# Search media_id in the catalog
		if media_id not in CATALOG:
			request.setResponseCode(404)
			request.responseHeaders.addRawHeader(b"content-type", b"application/json")
			return json.dumps({'error': 'media file not found'}).encode('latin')
		
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
			return json.dumps({'error': 'invalid chunk id'}).encode('latin')
			
		logger.debug(f'Download: chunk: {chunk_id}')

		offset = chunk_id * CHUNK_SIZE

		
		# Open file, seek to correct position and return the chunk
		with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
			f.seek(offset)
			data = f.read(CHUNK_SIZE)

			request.responseHeaders.addRawHeader(b"content-type", b"application/json")
			key,salt=self.derive_key(self.chunk_identification(session,chunk_id,media_id),session)
			data,iv=self.encrypt_message(data,session,key)
			#binascii.b2a_base64(data).decode('latin').strip(),
			return json.dumps(
					{
						'media_id': media_id, 
						'chunk': chunk_id, 
						'data': binascii.b2a_base64(data).decode('latin').strip(),
						'iv': base64.b64encode(iv).decode('latin'),
						'salt': base64.b64encode(salt).decode('latin'),
						'hmac': base64.b64encode(self.add_hmac(data,session,key)).decode('latin')
					},indent=4	
				).encode('latin')

		# File was not open?
		request.responseHeaders.addRawHeader(b"content-type", b"application/json")
		return json.dumps({'error': 'unknown'}, indent=4).encode('latin')


	def verify_hmac(self,session, recv_hmac, crypto, key=None):
		if key == None:
			key = session.shared_key
		h = None
		digest = None
		if session.digest == 'SHA-512':
			digest = hashes.SHA512()
		elif session.digest == 'SHA-256':
			digest = hashes.SHA256()
		size = self.key_sizes[session.cipher][0]
		h = hmac.HMAC(key[:size//8], digest)
		h.update(crypto)
		try:
			h.verify(recv_hmac)
			return True
		except:
			logger.info("HMAC Wrong. Communications will not continue")
			return False

	def verify_token(self,session,token,key=None):
		if key == None:
			key = session.shared_key
		h = None
		digest = None
		if session.digest == 'SHA-512':
			digest = hashes.SHA512()
		elif session.digest == 'SHA-256':
			digest = hashes.SHA256()
		size = self.key_sizes[session.cipher][0]
		h = hmac.HMAC(key[:size//8], digest)
		h.update(str(session.download_counter+1).encode('latin'))
		try:
			h.verify(token)
			return True
		except:
			logger.info("Download Token Wrong. Communications will not continue")
			return False



	def encrypt_message(self,text,session,key=None):
		#logger.debug("aaaaaaaaaaa",text)
		#logger.debug(text)
		if key == None:
			key = session.shared_key
		cipher=None
		algorithm,iv=None,None
		mode=None
		size=self.key_sizes[session.cipher][0]
		enc_shared_key=key[:size//8]
		logger.debug('Starting encription')
		#encryptor = cipher.encryptor()
		#ct = encryptor.update(b"a secret message") + encryptor.finalize()
		#decryptor = cipher.decryptor()
		#decryptor.update(ct) + decryptor.finalize()
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
			elif session.mode == 'GCM':
				mode = modes.GCM(iv)
			elif session.mode == 'CTR':
				mode = modes.CTR(iv)
			padder = padding.PKCS7(algorithm.block_size).padder()
			padded_data = padder.update(text)
			padded_data += padder.finalize()
			text=padded_data
					

		cipher = Cipher(algorithm, mode=mode)  
		encryptor = cipher.encryptor()
		#print(len(text))
		cryptogram = encryptor.update(text) + encryptor.finalize()
		#logger.debug(cryptogram,iv)
		return cryptogram, iv

	def add_hmac(self,message,session,key=None):
		
		if key == None:
			key=session.shared_key
		msg_bytes=None
		size=self.key_sizes[session.cipher][0]
		enc_shared_key=key[:size//8]
		if session.digest == 'SHA-512':
			h = hmac.HMAC(enc_shared_key, hashes.SHA512())
			h.update(message)
			msg_bytes = h.finalize() 
		elif session.digest == 'SHA-256':
			h = hmac.HMAC(enc_shared_key, hashes.SHA256())
			h.update(message)
			msg_bytes = h.finalize() 
		return msg_bytes


	def decrypt_message(self,cryptogram,iv,session,key=None):
		print(len(cryptogram))
		cipher=None
		algorithm=None
		mode=None
		if key==None:
			key=session.shared_key
		size = self.key_sizes[session.cipher][0]
		enc_shared_key = key[:size//8]
		#encryptor = cipher.encryptor()
		#ct = encryptor.update(b"a secret message") + encryptor.finalize()
		#decryptor = cipher.decryptor()
		#decryptor.update(ct) + decryptor.finalize()
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
		elif session.mode == 'GCM':
			mode = modes.GCM(iv)
		elif session.mode == 'CTR':
			mode = modes.CTR(iv)

		cipher = Cipher(algorithm, mode=mode)       

		decryptor = cipher.decryptor()
		if session.cipher == 'ChaCha20': 
			return decryptor.update(cryptogram) + decryptor.finalize()
		else:
			print(algorithm.block_size)
			padded_data = decryptor.update(cryptogram) + decryptor.finalize()
			unpadder = padding.PKCS7(algorithm.block_size).unpadder()
			text = unpadder.update(padded_data)	
			text += unpadder.finalize()
			return text


	def chunk_identification(self, session,chunk_id, media_id):
		media_id=media_id
		chunk_id=str(chunk_id)
		final_id=(session.shared_key.decode('latin')+media_id+chunk_id).encode('latin')
		algorithm=None
		if session.digest =='SHA-256':
			algorithm=hashes.SHA256()
		elif session.digest == 'SHA-512':
			algorithm = hashes.SHA512()
		digest=hashes.Hash(algorithm)
		digest.update(final_id)
		return digest.finalize()


	def derive_key(self, data,session,salt=None):
		digest=None
		if session.digest == 'SHA-512':
			digest = hashes.SHA512()
		elif session.digest == 'SHA-256':
			digest =hashes.SHA256()
		
		if salt == None:
			salt = os.urandom(16)
		# derive
		kdf = PBKDF2HMAC(
			algorithm=digest,
			length=32,
			salt=salt,
			iterations=10000,
		)
		key = kdf.derive(data)
		return key,salt

	def do_get_protocols(self,request):
		#receber os algoritmos e ver quais é o servidor tem
		print(request.content)


	def send_message(self,message):
		""" Encodes messages """
		message = json.dumps(message).encode('latin')
		return message

	def send_error_message(self,method):
		message=None
		if method=='NEGOTIATE_ALG':
			data={'method': 'ALG_ERROR'}
			message = json.dumps(data).encode('latin')
		
		else:
			data= {'method': 'KEY_ERROR'}
			message = json.dumps(data).encode('latin')
		return message
	
	

	def dh_key_gen(self,request):
		"""
		Generates the parameters necessary to start the Diffie-Hellman Algorithm
		along with the server private and public key.
		After that sends to client parameters and pub_key
		"""
		logger.debug('Generating parameters and keys...')
		
		session = self.check_session_id(request.getAllHeaders())
		if session == None:
			return json.dumps({'error': 'Session ID not found or not passed'}, indent=4).encode('latin')
		session.dh_parameters = dh.generate_parameters(generator=2, key_size=1024)
		session.private_key = session.dh_parameters.generate_private_key()
		session.public_key = session.private_key.public_key()
		parameter_num = session.dh_parameters.parameter_numbers()
		logger.debug('Generated keys and parameters with sucess')
		#print(parameter_num.g, parameter_num.p)
		pub_key=session.public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
		data = {'method':'DH_START','p':parameter_num.p,'g':parameter_num.g,'pub_key':pub_key}
		
		print(pub_key)
		return self.send_message(data)

	def negotiate_alg(self,data):
		logger.debug('CHECKING CIPHERS')
		client_ciphers,client_digests,client_ciphermodes=data['ciphers'],data['digests'],data['ciphermodes']
		availableciphers=[c for c in self.ciphers if c in client_ciphers]
		availabledigests=[c for c in  self.digests if c in client_digests]
		availablemodes=[c for c in self.ciphermodes if c in client_ciphermodes]
		if len(availableciphers)==0 or len(availabledigests) == 0  or len(availablemodes) == 0:
			logger.error('NO AVAILABLE CIPHERS,DIGESTS OR CIPHERMODES')
			return self.send_error_message('NEGOTIATE_ALG')
	
		# enviar mensagem a dizer q n pode
		#server chooses the cipher to communicate acordding to client's available ciphers
		session = Session()
		session.cipher = availableciphers[0]
		session.digest = availabledigests[0]
		session.mode=None
		if session.cipher!='ChaCha20':
			session.mode = availablemodes[0] 
		print(session.cipher,session.digest,session.mode)
		self.sessions[session.id] = session
		logger.debug('Success checking ciphers')
		#enviar 
		print(self.certificate)
		message = {
			'method': 'NEGOTIATE_ALG',
			'id':session.id,
			'cipher':session.cipher,
			'mode':session.mode,
			'digest':session.digest,
			'cert' : base64.b64encode(self.certificate.public_bytes(serialization.Encoding.PEM)).decode('latin')
			}
		return self.send_message(message)
		
	
	def dh_exchange_key(self,request):
		data= json.loads(request.content.getvalue())
		session = self.check_session_id(request.getAllHeaders())
		print(session)
		if session !=None:
			method=data['method']
			if method =='KEY_EXCHANGE':
				logger.debug('Confirmed the exchange of a key')
				received_key=data['pub_key'].encode()
				#received_key = self.sign_message(received_key)
				logger.debug(received_key)
				session.client_pub_key=load_pem_public_key(received_key)
				session.shared_key = session.private_key.exchange(session.client_pub_key)
				message = {'method':'ACK'}
				return self.send_message(message)

		logger.debug('Could not exchange a key. oof')
		return self.send_error_message('NACK')
		
		
	def accept_challenge(self,request,session,msg,iv,key):
		
		data = json.loads(self.decrypt_message(msg,iv,session,key))
		nonce = data['nonce'].encode('latin')
		client_cert = data['cert'].encode('latin')
		session.cert = x509.load_pem_x509_certificate(client_cert)
		logger.debug("Got Nonce and Client Certificate. Validating Certificate..")
		if not self.validate_certificate(session.cert):
			logger.debug("Client certificate is not valid!")
			return None

		snonce = self.sign_message(nonce)
		nonce2=os.urandom(16)
		session.nonce2 = nonce2
		
		message=json.dumps({
			'snonce':snonce.decode('latin'),
			'nonce2':nonce2.decode('latin')
		}).encode('latin')
		key, salt = self.derive_key(session.shared_key,session)
		message,iv = self.encrypt_message(message,session,key)
		
		message = json.dumps({
			'message':base64.b64encode(message).decode('latin'),
			'iv':base64.b64encode(iv).decode('latin'),
			'salt':base64.b64encode(salt).decode('latin'),
			'hmac':base64.b64encode(self.add_hmac(message,session,key)).decode('latin')
			})

		return message.encode('latin')

	def verify_challenge(self,request,session,crypt,iv,key):
		logger.debug("Verifing Challenge")
		data = json.loads(self.decrypt_message(crypt,iv,session,key))
		nonce2 = data['snonce2'].encode('latin')
		message=None
		key, salt = self.derive_key(session.shared_key,session)
		#session.cert.public_key().verify(session.nonce2,nonce2, pd.PKCS1v15(), hashes.SHA1()) 

		#try:
	
		logger.debug("Challenge OK")
		message=json.dumps({
			'method':'ACK'
		}).encode('latin')

		
			#message=json.dumps({
				#'method':'NACK'
			#}).encode('latin')
		
			#logger.info("Challenge wrong. Comms Compromised")
		session.user = 1 # TODO:SERIALNUMBER do cc
		message,iv = self.encrypt_message(message,session,key)
		response = json.dumps({
		'message':base64.b64encode(message).decode('latin'),
		'iv':base64.b64encode(iv).decode('latin'),
		'salt':base64.b64encode(salt).decode('latin'),
		'hmac':base64.b64encode(self.add_hmac(message,session,key)).decode('latin')
		}).encode('latin')	
		logger.debug("ns vamos ver")
		return response			
		
	def start_download(self,request,session,crypt,iv,key):
		print(type(crypt),type(iv))
		data = json.loads(self.decrypt_message(crypt,iv,session,key))
		license=data['license'].encode('latin')
		media_id = data['media_id'].encode('latin')
		key, salt = self.derive_key(session.shared_key,session)
		license = x509.load_pem_x509_certificate(license)
		if self.validate_license(license,media_id):
			download_token = int.from_bytes(os.urandom(16), sys.byteorder) 
			session.download_token = download_token
			content,iv=self.encrypt_message(json.dumps({'method':'GET_TOKEN','download_token':session.download_token.decode('latin')}).encode('latin'),session,key)
			response=json.dumps({
				'message':base64.b64encode(content).decode('latin'),
				'iv':base64.b64encode(iv).decode('latin'),
				'salt':base64.b64encode(salt).decode('latin'),
				'hmac':base64.b64encode(self.add_hmac(content,session,key)).decode('latin')
				})
			return response.encode('latin')
		

	def send_license(self,session,media_id):
		cert = self.gen_license(session,media_id)
		key, salt = self.derive_key(session.shared_key,session)
		content,iv = self.encrypt_message(json.dumps({'method':'GET_LICENSE','license':cert.public_bytes(serialization.Encoding.PEM).decode('latin')}).encode('latin'),session,key)
		response=json.dumps({'message':base64.b64encode(content).decode('latin'),
		'iv':base64.b64encode(iv).decode('latin'),
		'salt':base64.b64encode(salt).decode('latin'),
		'hmac':base64.b64encode(self.add_hmac(content,session,key)).decode('latin'),
		})
		return response.encode('latin')



	def do_post_protocols(self,request):
		data = json.loads(request.content.getvalue())
		method=data['method']
		if method == 'NEGOTIATE_ALG':
			return self.negotiate_alg(data)
		elif method == 'KEY_EXCHANGE':
			return self.key_exchange(data)


	# Handle a GET request
	def render_GET(self, request):
		logger.debug(f'Received request for {request.uri}')
		print(request.uri)

		try:
			if request.path == b'/api/protocols':
				return self.do_get_protocols(request)
			elif request.path == b'/api/key':
			#...chave publica do server
				request.responseHeaders.addRawHeader(b"content-type", b"application/json")
				logger.debug("entrei")
				return self.dh_key_gen(request)
			elif request.uri == b'/api':
				#decript da mensagem
				#ver o metodo e responder
				data = request.getAllHeaders()
				session=self.check_session_id(data)
				iv = base64.b64decode(data[b'iv'].decode())
				salt=base64.b64decode(data[b'salt'].decode())
				content = base64.b64decode(data[b'content'].decode())
				hmac = base64.b64decode(data[b'hmac'].decode())
				key,_=self.derive_key(session.shared_key,session,salt)			
				data = self.decrypt_message(content,iv,session,key).decode('latin')
				data = json.loads(data.encode())
				method = data.get('method')
				

				if method == 'GET_LIST':
					if not self.verify_hmac(session,hmac,content,key):
						logger.debug("HMAC WRONG")
					else:
						logger.debug("HMAC OK")
						return self.do_list(request,session)
				elif method == "DOWNLOAD":
					chunk_id = data.get('chunk_id')
					media_id = data.get('media_id')
					token = data.get('token').encode('latin')
					exp_token = str(session.download_counter+1).encode('latin')
					if not self.verify_token(session,token,key):
						logger.debug("Invalid Download token!")
						return		#TODO:mensagem de erro
					else:
						print(chunk_id,media_id)
						if media_id is None:
							request.setResponseCode(400)
							request.responseHeaders.addRawHeader(b"content-type", b"application/json")
							return json.dumps({'error': 'invalid media id'}).encode('latin')
						session.download_token+=1
						return self.do_download(request,session,media_id,int(chunk_id))
				elif method == 'GET_LICENSE':
					media_id = data.get('media_id')
					return self.send_license(session,media_id)
			#elif request.uri == 'api/auth':
			#autenticaçao, later on..
			#elif request.path == b'/api/list':
			#	#request.responseHeaders.addRawHeader(b"content-type", b"application/json")
			#	a=self.do_list(request)
			#	logger.debug('finished encryption')
			#	return a

			#elif request.path == b'/api/download':
			#	return self.do_download(request)
			#else:
			#	request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
			#	return b'Methods: /api/protocols /api/list /api/download'
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
				return self.do_post_protocols(request)
			elif request.uri == b'/api/key':
				return self.dh_exchange_key(request)
			elif request.uri == b'/api':
				#read headers content
				data = request.getAllHeaders()
				session=self.check_session_id(data)
				iv = base64.b64decode(data[b'iv'].decode())
				salt=base64.b64decode(data[b'salt'].decode())
				content = base64.b64decode(data[b'content'].decode())
				key,_=self.derive_key(session.shared_key,session,salt)
				data = self.decrypt_message(content,iv,session,key).decode('latin')
				data = json.loads(data.encode())
				method = data.get('method')
				# read post body
				data= json.loads(request.content.getvalue())

				msg = base64.b64decode(data['data'])
				iv=base64.b64decode(data['iv'])
				hmac=base64.b64decode(data['hmac'])
				if not self.verify_hmac(session,hmac,msg,key):
					logger.debug("Ups HMAC Wrong")
				else:
					if method == 'START_CHALLENGE':
						logger.debug("START CHALLENGE")
						return self.accept_challenge(request,session,msg,iv,key)
					elif method == 'ACCEPT_CHALLENGE':
						logger.debug("ACCEPT CHALLENGE")
						return self.verify_challenge(request,session,msg,iv,key)
					elif method == 'START_DOWNLOAD':
						logger.debug("START DOWNLOAD")
						return self.start_download(request,session,msg,iv,key)

		except Exception as e:
			logger.exception(e)
			request.setResponseCode(500)
			request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
			return b''

		#request.setResponseCode(501) #Not implemented
		return b''


print("Server started")
print("URL is: http://IP:8080")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()    
