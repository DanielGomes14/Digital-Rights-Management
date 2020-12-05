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

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'

class Client:
    def __init__(self):
        """Representation of the client."""

        self.ciphers = ['AES']
        self.digests = ['SHA-256','SHA-512']
        self.ciphermodes = ['CBC','ECB','GCM']
        self.srvr_publickey =None
        self.cipher = None
        self.digest = None
        self.ciphermode = None
        self.key_sizes = {'3DES':[10,10]}
        
    def has_negotiated(self):
        return not (self.cipher is None or self.digest is None or self.digest is None)


    def send_message(self,method):
        #Negotiate algorithms
        data=None
        if self.srvr_publickey: 
            if method == 'ALG': # TODO: 
                #if the algorithms have not been negotiated yet
                if not self.has_negotiated() : 
                    logger.info('Sending POST Request to start negotiating')
                    #Send to the server client's available types of ciphers,digests, and ciphermodes
                    data = {'method':method, 'ciphers':self.ciphers, 'digests':self.digests, 'ciphermodes':self.ciphermodes}
                    request = requests.post(f'{SERVER_URL}/api/protocols',json=data,headers={'Content-Type': 'application/json'})
                    
                    return request.text
            else:
                pass
        else:
            # if public key is not known
            logger.info('Sending GET Request to get Public Key')
            response = requests.get(f'{SERVER_URL}/api/key')
            server_pubkey = json.loads(response.content.decode('latin'))
            if server_pubkey != None and 'KEY'  in server_pubkey: 
                self.srvr_publickey=server_pubkey['KEY']
                logger.info('GOT KEY')
        
    def encrypt_msg(self,message):
        #see what algorithm is been use
        if self.cipher == '3DES':
            pass    
        elif self.cipher == 'AES':
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
    print(client.send_message('ALG'))

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