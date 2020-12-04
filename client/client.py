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

        self.ciphers = []
        self.digests = ['SHA-256','SHA-512']
        self.ciphermodes = ['CBC','ECB']
        self.srvr_publickey =None
        self.cipher = None
        self.digest = None
        self.ciphermode = None
    
    def send_message(self,method):
        #Negotiate algorithms
        if method == 'ALG': # TODO: 
            #when we dont have the server public key yet
            if not self.srvr_publickey: 
            #Send to the server client's available types of ciphers,digests, and ciphermodes
                data = json.dumps({'method':method, 'ciphers':self.ciphers, 'digests':self.digests, 'ciphermode':self.ciphermode})
        else:
            pass



def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    # Get a list of media files
    print("Contacting Server")
    
    
    # TODO: Secure the session
    client = Client()
    # get server public key
    
    req = requests.get(f'{SERVER_URL}/api/key')
    if req:
        print(req.content)

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