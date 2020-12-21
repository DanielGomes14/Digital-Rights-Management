import requests
import logging
import binascii
import json
import os
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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'


class Client:
	def __init__(self):
		"""Representation of the client."""

		self.ciphers = ['AES', '3DES', 'ChaCha20']
		self.digests = ['SHA-512', 'SHA-256']
		self.ciphermodes = ['CBC', 'CTR', 'GCM']
		self.srvr_publickey = None
		self.cipher = None
		self.digest = None
		self.ciphermode = None
		self.key_sizes = {'3DES': [192, 168, 64],
			'AES': [256, 192, 128], 'ChaCha20': [256]}
		self.dh_parameters = None

	def has_negotiated(self):
		return not (self.cipher is None or self.digest is None)

	def dh_start(self):
		""" Diffie-Helman: get parameters and generate public and private key  """
		
		# GET request for the parameters and server public key
		response = requests.get(f'{SERVER_URL}/api/key')
		logger.info('Received parameters and Public Key with sucess')
		data = json.loads(response.text)
		print(data)
		p = data['p']
		g = data['g']

		# generates public and private key using the parameters
		pn = dh.DHParameterNumbers(p, g)
		self.dh_parameters = pn.parameters()
		self.private_key = self.dh_parameters.generate_private_key()
		self.public_key = self.private_key.public_key()
		
		#stores server public key
		received_key = data['pub_key'].encode()
		self.srvr_publickey = load_pem_public_key(received_key)
		

	def dh_exchange_key(self):
		""" Exchange keys with the server"""
		
		logger.info('Sending POST Request to exchange DH Shared key')
		key = self.public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
		data = {
			'id' : self.session_id,
			'method': 'KEY_EXCHANGE',
			'pub_key': key
		}
		# POST request sending public key
		request = requests.post(f'{SERVER_URL}/api/key', json=data, headers={'Content-Type': 'application/json'})
		data = json.loads(request.text)
		print(data)
		method = data['method']
		if method == 'ACK':
			logger.info('Server confirmed the exchange')
			self.shared_key = self.private_key.exchange(self.srvr_publickey)
		else:
			logger.info('Could not exchange a key with the server')

	def negotiate_algs(self):
		data = {
			'method': "NEGOTIATE_ALG",
			'ciphers': self.ciphers,
			'digests': self.digests,
			'ciphermodes': self.ciphermodes
		}
		request = requests.post(f'{SERVER_URL}/api/protocols',json=data, headers={'Content-Type': 'application/json'})
		response = json.loads(request.text)
		
		if response['method'] == 'ALG_ERROR':
			logger.info('ERROR NEGOTIATING ALGORITHMS')
		else:
			logger.info(' NEGOTIATED ALGORITHMS WITH SUCCESS')
			self.session_id=response['id']
			self.cipher, self.digest, self.ciphermode = response['cipher'], response['digest'], response['mode']

	def encrypt_message(self, text):
		iv = os.urandom(16)
		cipher = None
		algorithm, iv = None, None
		mode = None
		#encryptor = cipher.encryptor()
		#ct = encryptor.update(b"a secret message") + encryptor.finalize()
		#decryptor = cipher.decryptor()
		#decryptor.update(ct) + decryptor.finalize()
		if self.cipher == 'AES':
			algorithm = algorithms.AES(self.shared_key)
		elif self.cipher == '3DES':
			algorithm = algorithms.size
			algorithm = algorithms.ChaCha20(self.shared_key, iv)
		else:
			logger.debug('Algorithm not suported')
		if self.cipher != 'ChaCha20':
			# with ChaCha20 we do not pad the data
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

	def decrypt_message(self, cryptogram, iv, key=None):
		if key == None:
			key = self.shared_key
		cipher = None
		algorithm = None
		mode = None
		size = self.key_sizes[self.cipher][0]
		enc_shared_key = key[:size//8]
		#encryptor = cipher.encryptor()
		#ct = encryptor.update(b"a secret message") + encryptor.finalize()
		#decryptor = cipher.decryptor()
		#decryptor.update(ct) + decryptor.finalize()
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
		elif self.ciphermode == 'GCM':
			mode = modes.GCM(iv)
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

	def add_hmac(self, message, key=None):
		if key == None:
			key = self.shared_key
		msg_bytes = None
		if self.digest == 'SHA-512':
			h = hmac.HMAC(key, hashes.SHA512())
			h.update(message)
			msg_bytes = h.finalize()
		elif self.digest == 'SHA-256':
			h = hmac.HMAC(key, hashes.SHA256())
			h.update(message)
			msg_bytes = h.finalize()
		return msg_bytes

	def chunk_identification(self, chunk_id, media_id):
		media_id=media_id
		chunk_id=str(chunk_id)
		final_id=(self.shared_key.decode('latin')+media_id+chunk_id).encode('latin')
		logger.info(final_id)
		algorithm=None
		if self.digest =='SHA-256':
			algorithm=hashes.SHA256()
		elif self.digest == 'SHA-512':
			algorithm = hashes.SHA512()
		digest=hashes.Hash(algorithm)
		digest.update(final_id)
		return digest.finalize()


	def derive_key(self, data, salt):
		digest=None
		if self.digest == 'SHA-512':
			digest = hashes.SHA512()
		elif self.digest == 'SHA-256':
			digest =hashes.SHA256()
		
		# derive
		kdf = PBKDF2HMAC(
			algorithm=digest,
			length=32,
			salt=salt,
			iterations=100000,
		)
		key = kdf.derive(data)
		return key


	def verify_hmac(self, recv_hmac, crypto, key=None):
		if key == None:
			key = self.shared_key
		h = None
		digest = None
		if self.digest == 'SHA-512':
			digest = hashes.SHA512()
		elif self.digest == 'SHA-256':
			digest = hashes.SHA256()
		size = self.key_sizes[self.cipher][0]
		h = hmac.HMAC(key[:size//8], digest)
		h.update(crypto)
		try:
			h.verify(recv_hmac)
			return True
		except:
			logger.info("HMAC Wrong. Communications will not continue")
			return False

	def get_list(self):
		req = requests.get(f'{SERVER_URL}/api/list')
		if req.status_code == 200:
			print("Got Server List")
		data = json.loads(req.text)
		cryptogram = base64.b64decode(data['cryptogram'])
		iv = base64.b64decode(data['iv'])
		print(len(iv))
		hmac = base64.b64decode(data['hmac'])
		logger.info("verifying hmac..")
		verif = self.verify_hmac(hmac, cryptogram)
		if verif:
			logger.info("HMAC OK")
			media_list = json.loads(self.decrypt_message(cryptogram, iv))
			return media_list
		else:
			logger.info("HMAC Wrong. Communications Compromised")
			return None

	def list_media_content(self,media_list):
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
		return media_item		

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
	# if req:
	# print(req.content)
	if not client.has_negotiated():
		client.negotiate_algs()
		client.dh_start()
		client.dh_exchange_key()
	# client.send_message('')

	# client or server sends the algorithms to be used and the other sends the response (encoded with public?)

	# client generates simetric key and sends it encrypted with server public key

	# validate all messages with MAC (calculate hash negotiated from last step and prepend it in the end)
	media_list=None
	if client.shared_key!=None:
		media_list=client.get_list()
		print(media_list)
	
	#media_list = req.json()
	media_item=None
	if media_list != None:
		media_item=client.list_media_content(media_list)
		print(media_item)
	# Present a simple selection menu

	print(f"Playing {media_item['name']}")

	# Detect if we are running on Windows or Linux
	# You need to have ffplay or ffplay.exe in the current folder
	# In alternative, provide the full path to the executable
	if os.name == 'nt':
		proc = subprocess.Popen(
			['ffplay.exe', '-i', '-'], stdin=subprocess.PIPE)
	else:
		proc = subprocess.Popen(['ffplay', '-i', '-'], stdin=subprocess.PIPE)

	# Get data from server and send it to the ffplay stdin through a pipe
	for chunk in range(media_item['chunks'] + 1):
		req = requests.get(
			f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}')

		chunk = req.json()
		data = binascii.a2b_base64(chunk['data'].encode('latin'))
		iv, salt = base64.b64decode(chunk['iv']), base64.b64decode(chunk['salt'])
		hmac = base64.b64decode(chunk['hmac'])
		logger.info(chunk['chunk'])
		logger.info(chunk['media_id'])
		key = client.derive_key(client.chunk_identification(chunk['chunk'], chunk['media_id']), salt)
		verif = client.verify_hmac(hmac, data, key)
		if verif:
			logger.info("HMAC OK")
			data = client.decrypt_message(data, iv, key)
			# TODO: Process chunk
			logger.info(data)
			#data = binascii.a2b_base64(data)
			try:
				proc.stdin.write(data)
			except:
				break
		else:
			logger.info("HMAC Wrong. Communications compromised")
			exit(0)


if __name__ == '__main__':

	while True:
		main()
		time.sleep(1)
