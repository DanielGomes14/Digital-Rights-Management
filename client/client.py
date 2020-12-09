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
from cryptography.hazmat.primitives.asymmetric import rsa  
from cryptography.hazmat.primitives import serialization  
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import utils

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
        self.key_sizes = {'3DES':[64,128,192],'AES':[128,192,256],'ChaCha20':[256]}
        
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
                

    def send_message(self,method):
        #Negotiate algorithms
        data=None
        if self.srvr_publickey: 
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
            elif method == 'EXCHANGE_KEY':
                logger.info('Sending POST Request to start exchanging a common key')
                key = self.generate_key().decode('latin')
                
                
                ciphertext = self.srvr_publickey.encrypt(key,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
                
                data = {'method':method,'key':key}            
                request = requests.post(f'{SERVER_URL}/api/key',json=data,headers={'Content-Type': 'application/json'})
                response=json.loads(request.text)
                if response['method']== 'KEY_ERROR':
                    logger.info('COULD NOT EXCHANGE A KEY')
                else:
                    logger.info('EXCHANGED KEY WITH SUCESS')
            else:
                pass
        else:
            # if public key is not known
            self.request_publickey()

    
    
    
    
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
    client.send_message(None)
    client.send_message('NEGOTIATE_ALG')
    client.send_message('EXCHANGE_KEY')

    # client or server sends the algorithms to be used and the other sends the response (encoded with public?)

    

    # client generates simetric key and sends it encrypted with server public key 
    


    # validate all messages with MAC (calculate hash negotiated from last step and prepend it in the end)

    
    
    req = requests.get(f'{SERVER_URL}/api/list')
    if req.status_code == 200:
        print("Got Server List")

    media_list = req.json()



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