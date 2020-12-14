import requests
import logging
import binascii
import json
import os
import random
import subprocess
import time
import sys
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend  
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF    
from cryptography.hazmat.backends.interfaces import RSABackend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'

class Client:
	def __init__(self):
		"""Representation of the client."""

		self.ciphers = ['AES','3DES','ChaCha20']
		self.digests = ['SHA-256','SHA-512']
		self.ciphermodes = ['CBC','CTR','GCM']
		self.srvr_publickey =None
		self.cipher = None
		self.digest = None
		self.ciphermode = None
		self.key_sizes = {'3DES':[192,168,64],'AES':[256,192,128],'ChaCha20':[256]}
		self.dh_parameters = None


	def has_negotiated(self):
		return not (self.cipher is None or self.digest is None or self.digest is None)


	def request_publickey(self):
		logger.info('Sending GET Request to get Public Key')
		response = requests.get(f'{SERVER_URL}/api/key')
		server_pubkey = json.loads(response.content.decode('latin'))
		if server_pubkey != None and 'KEY'  in server_pubkey: 
			received_key=server_pubkey['KEY'].encode()
			key = load_pem_public_key(received_key)
			if isinstance(key, rsa.RSAPublicKey):
				logger.info('GOT KEY')
				self.srvr_publickey=key
			else:
				logger.info('NOT KEY')

	def dh_start(self,data):
		p = data['p']
		g = data['g']
		pn= dh.DHParameterNumbers(p,g)
		self.dh_parameters = pn.parameters()
		self.private_key = self.dh_parameters.generate_private_key()
		self.public_key = self.private_key.public_key()
		received_key=data['pub_key'].encode()
		self.srvr_publickey=load_pem_public_key(received_key)
		print(self.srvr_publickey)

	def dh_exchange_key(self,data):
		method=data['method']
		if method == 'ACK':
			logger.info('Server confirmed the exchange')
			self.shared_key = self.private_key.exchange(self.srvr_publickey)
		else:
			logger.info('Could not exchange a key with the server')


	def send_message(self,method):
		#Negotiate algorithms
		data=None
		if not self.srvr_publickey: 
			if method == 'NEGOTIATE_ALG': # TODO: 
				#if the algorithms have not been negotiated yet
				if not self.has_negotiated() : 
					logger.info('Sending POST Request to start negotiating')
					#Send to the server client's available types of ciphers,digests, and ciphermodes
					data = {'method':method, 'ciphers':self.ciphers, 'digests':self.digests, 'ciphermodes':self.ciphermodes}
					request = requests.post(f'{SERVER_URL}/api/protocols',json=data,headers={'Content-Type': 'application/json'})
					response=json.loads(request.text)
					if response['method'] == 'ALG_ERROR':
						logger.info('ERROR NEGOTIATING ALGORITHMS')
					else:
						logger.info(' NEGOTIATED ALGORITHMS WITH SUCCESS')

						self.cipher,self.digest,self.ciphermode=response['cipher'],response['digest'],response['mode']    
			elif method == 'DH_START':
				logger.info('Sending POST Request to Start DH')
				if not self.dh_parameters:
					response = requests.get(f'{SERVER_URL}/api/key')
					logger.info('Received parameters and Public Key with sucess')
					data = json.loads(response.text)
					self.dh_start(data)
					logger.info('Sending POST Request to exchange DH Shared key')
					key=self.public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
					data = {'method': 'KEY_EXCHANGE','pub_key': key}
					request = requests.post(f'{SERVER_URL}/api/key',json=data,headers={'Content-Type': 'application/json'})
					logger.debug("test...")
					response= json.loads(request.text)
					self.dh_exchange_key(response)
					
			else:
				pass
		else:
			# if public key is not known
			self.request_publickey()

	
	
	def dh_key_gen(self):
		if self.parameters is not None:
			pass
	
	
	def generate_key(self):
		"""
		Used to generate a ephemeral key to comunicate with the server 
		"""
		#TODO: random to choose which one to use
		key_size = self.key_sizes[self.cipher][0]
		key = os.urandom(key_size)

		return key


		
	def encrypt_msg(self,message):
		#see what algorithm is been use
		cipher = None
		if self.cipher == '3DES':
			pass    
		elif self.cipher == 'AES':
			iv=os.urandom()
			cipher = Cipher(algorithms.AES(self.srvr_publickey), modes.CBC(iv))
			encryptor = cipher.encryptor()
			ct = encryptor.update(b"a secret message")
			#cipher = Cipher(algorithms.AES(se), modes.CBC(iv))
		elif self.cipher == 'ChaCha20':
			pass
			
			
		return message
	
	def encrypt_message(self,text):
		iv = os.urandom(16)
		cipher=None
		algorithm,iv=None,None
		mode=None
		#encryptor = cipher.encryptor()
		#ct = encryptor.update(b"a secret message") + encryptor.finalize()
		#decryptor = cipher.decryptor()
		#decryptor.update(ct) + decryptor.finalize()
		if self.cipher == 'AES':
			algorithm = algorithms.AES(self.shared_key)
		elif self.cipher == '3DES':
			algorithm = algorithms.TripleDES(self.shared_key)
		elif self.cipher == 'ChaCha20':
			iv = os.random(16)
			algorithm = algorithms.ChaCha20(self.shared_key,iv)
		else:
			logger.debug('Algorithm not suported')
		if self.cipher != 'ChaCha20':
			#with ChaCha20 we do not pad the data
			iv = os.random(16)
			
			if self.ciphermode == 'CBC':
				mode = modes.CBC(iv)
			elif self.ciphermode == 'GCM':
				mode = modes.GCM(iv)
			elif self.ciphermode == 'CTR':
				mode = modes.CTR(iv)
			padder = padding.PKCS7(self.key_sizes[self.cipher][0]).padder()
			padded_data = padder.update(text)
			padded_data += padder.finalize()
					
		cipher = Cipher(algorithm, mode=mode)    
		encryptor = cipher.encryptor()
		cryptogram = encryptor.update(text) + encryptor.finalize()

		return cryptogram, iv

	def decrypt_message(self,cryptogram,iv):
		cipher=None
		algorithm=None
		mode=None
		size=self.key_sizes[self.cipher][0]
		enc_shared_key=self.shared_key[:size//8]
		iv=iv.encode('latin')
		cryptogram=cryptogram.encode('latin')
		#encryptor = cipher.encryptor()
		#ct = encryptor.update(b"a secret message") + encryptor.finalize()
		#decryptor = cipher.decryptor()
		#decryptor.update(ct) + decryptor.finalize()
		if self.cipher == 'AES':
			algorithm = algorithms.AES(enc_shared_key)
		elif self.cipher == '3DES':
			algorithm = algorithms.TripleDES(enc_shared_key)
		elif self.cipher == 'ChaCha20':
			if iv!=None:algorithm = algorithms.ChaCha20(enc_shared_key)
		else:
			logger.debug('Algorithm not suported')

		#with ChaCha20 we do not pad the data
		if self.ciphermode == 'CBC':
			mode = modes.CBC(iv)
		elif self.ciphermode == 'GCM':
			mode = modes.GCM(iv)
		elif self.ciphermode == 'CTR':
			mode = modes.CTR(iv)
		cipher = Cipher(algorithm, mode=mode)       
		decryptor = cipher.decryptor()
		if algorithm == 'ChaCha20': 
			return decryptor.update(cryptogram) + decryptor.finalize()
		else:
			padded_data = decryptor.update(cryptogram) + decryptor.finalize()	
			unpadder = padding.PKCS7(algorithm.block_size).unpadder()
			text = unpadder.update(padded_data)
			text += unpadder.finalize()
			return list(json.loads(text.decode('latin')))



def main():
	print("|--------------------------------------|")
	print("|         SECURE MEDIA CLIENT          |")
	print("|--------------------------------------|\n")

	# Get a list of media files
	print("Contacting Server")
	
	
	# TODO: Secure the session
	client = Client()

	# get server public key
	
	#req = requests.get(f'{SERVER_URL}/api/key')
	#if req:
		#print(req.content)
	client.send_message('NEGOTIATE_ALG')
	client.send_message('DH_START')
	#client.send_message('')

	# client or server sends the algorithms to be used and the other sends the response (encoded with public?)

	

	# client generates simetric key and sends it encrypted with server public key 
	


	# validate all messages with MAC (calculate hash negotiated from last step and prepend it in the end)

	
	
	req = requests.get(f'{SERVER_URL}/api/list')
	if req.status_code == 200:
		print("Got Server List")
	data=json.loads(req.text)
	cryptogram=data['cryptogram']
	iv = data['iv']
	media_list = client.decrypt_message(cryptogram,iv)
	print(media_list)
 	#media_list = req.json()



	# Present a simple selection menu    
	idx = 0
	print("MEDIA CATALOG\n")
	for item in media_list:
		print(f'{idx} - {media_list[idx]["name"]}')
	print("----")

	while True:
		selection = input("Select a media file number (q to quit): ")
		if selection.strip() == 'q':
			sys.exit(0)

		if not selection.isdigit():
			continue

		selection = int(selection)
		if 0 <= selection < len(media_list):
			break

	# Example: Download first file
	media_item = media_list[selection]
	print(f"Playing {media_item['name']}")

	# Detect if we are running on Windows or Linux
	# You need to have ffplay or ffplay.exe in the current folder
	# In alternative, provide the full path to the executable
	if os.name == 'nt':
		proc = subprocess.Popen(['ffplay.exe', '-i', '-'], stdin=subprocess.PIPE)
	else:
		proc = subprocess.Popen(['ffplay', '-i', '-'], stdin=subprocess.PIPE)

	# Get data from server and send it to the ffplay stdin through a pipe
	for chunk in range(media_item['chunks'] + 1):
		req = requests.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}')
		chunk = req.json()
		# TODO: Process chunk

		data = binascii.a2b_base64(chunk['data'].encode('latin'))
		try:
			proc.stdin.write(data)
		except:
			break

if __name__ == '__main__':

	#sacar a public key
	

	while True:
		main()
		time.sleep(1)