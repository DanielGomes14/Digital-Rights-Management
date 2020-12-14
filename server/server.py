#!/usr/bin/env python

from twisted.web import server, resource
from twisted.internet import reactor, defer
from cryptography.hazmat.backends.interfaces import RSABackend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
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

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

CATALOG = { '898a08080d1840793122b7e118b27a95d117ebce': 
            {
                'name': 'Sunny Afternoon - Upbeat Ukulele Background Music',
                'album': 'Upbeat Ukulele Background Music',
                'description': 'Nicolai Heidlas Music: http://soundcloud.com/nicolai-heidlas',
                'duration': 3*60+33,
                'file_name': '898a08080d1840793122b7e118b27a95d117ebce.mp3',
                'file_size': 3407202
            }
        }

CATALOG_BASE = 'catalog'
CHUNK_SIZE = 1024 * 4

class MediaServer(resource.Resource):
    isLeaf = True
    def __init__(self):
        #self.ciphers=[]
        #self.digests=[]
        #self.ciphermodes=[]
        self.ciphers = ['AES','3DES','ChaCha20']
        self.digests = ['SHA-256','SHA-384','SHA-512']
        self.ciphermodes = ['CBC','GCM','CTR']
        self.key_sizes = {'3DES':[192,168,64],'AES':[256,192,128],'ChaCha20':[256]}
        self.public_key,self.private = None,None
        self.shared_key=None
        self.dh_parameters = None
        
    # Send the list of media files to clients
    def do_list(self, request):

        #auth = request.getHeader('Authorization')
        #if not auth:
        #    request.setResponseCode(401)
        #    return 'Not authorized'


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

        # Return list to client
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return self.encrypt_message(json.dumps(media_list).encode('latin'))
        #return json.dumps(media_list, indent=4).encode('latin')


    # Send a media chunk to the client
    def do_download(self, request):
        logger.debug(f'Download: args: {request.args}')
        media_id = request.args.get(b'id', [None])[0]
        logger.debug(f'Download: id: {media_id}')

        # Check if the media_id is not None as it is required
        if media_id is None:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'invalid media id'}).encode('latin')
        
        # Convert bytes to str
        media_id = media_id.decode('latin')

        # Search media_id in the catalog
        if media_id not in CATALOG:
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'media file not found'}).encode('latin')
        
        # Get the media item
        media_item = CATALOG[media_id]

        # Check if a chunk is valid
        chunk_id = request.args.get(b'chunk', [b'0'])[0]
        valid_chunk = False
        try:
            chunk_id = int(chunk_id.decode('latin'))
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
            return json.dumps(
                    {
                        'media_id': media_id, 
                        'chunk': chunk_id, 
                        'data': binascii.b2a_base64(data).decode('latin').strip()
                    },indent=4
                ).encode('latin')

        # File was not open?
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps({'error': 'unknown'}, indent=4).encode('latin')


    def encrypt_message(self,text):
        logger.debug("aaaaaaaaaaa",text)
        logger.debug(text)
        cipher=None
        algorithm,iv=None,None
        mode=None
        size=self.key_sizes[self.cipher][0]
        enc_shared_key=self.shared_key[:size//8]
        logger.debug('Starting encription')
        #encryptor = cipher.encryptor()
        #ct = encryptor.update(b"a secret message") + encryptor.finalize()
        #decryptor = cipher.decryptor()
        #decryptor.update(ct) + decryptor.finalize()
        if self.cipher == 'AES':
            algorithm = algorithms.AES(enc_shared_key)

        elif self.cipher == '3DES':
            algorithm = algorithms.TripleDES(enc_shared_key)
        elif self.cipher == 'ChaCha20':
            iv = os.urandom(16)
            algorithm = algorithms.ChaCha20(enc_shared_key,iv)
        else:
            logger.debug('Algorithm not suported')
        if self.cipher != 'ChaCha20':
            #with ChaCha20 we do not pad the data
            iv = os.urandom(16)
            
            if self.mode == 'CBC':
                mode = modes.CBC(iv)
            elif self.mode == 'GCM':
                mode = modes.GCM(iv)
            elif self.mode == 'CTR':
                mode = modes.CTR(iv)
            logger.debug("oof")

            padder = padding.PKCS7(algorithm.block_size).padder()
            padded_data = padder.update(text)
            padded_data += padder.finalize()
            text=padded_data
                    

        cipher = Cipher(algorithm, mode=mode)  
        encryptor = cipher.encryptor()
        print(len(text))
        cryptogram = encryptor.update(text) + encryptor.finalize()

        return cryptogram, iv

    def decrypt_message(self,cryptogram,iv):
        cipher=None
        algorithm=None
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
            if iv!=None:algorithm = algorithms.ChaCha20(self.shared_key,iv)
        else:
            logger.debug('Algorithm not suported')

        #with ChaCha20 we do not pad the data
        if self.mode == 'CBC':
            mode = modes.CBC(iv)
        elif self.mode == 'GCM':
            mode = modes.GCM(iv)
        elif self.mode == 'CTR':
            mode = modes.CTR(iv)

        cipher = Cipher(algorithm, mode=mode)       

        decryptor = cipher.decryptor()
        if algorithm == 'ChaCha20': return decryptor.update(cryptogram) + decryptor.finalize()
        else:
            padded_data = decryptor.update(cryptogram) + decryptor.finalize()
            unpadder = padding.PKCS7(self.key_sizes[self.cipher][0]).unpadder()
            text = unpadder.update(padded_data)
            text += unpadder.finalize()
            return text


    def do_get_protocols(self,request):
        #receber os algoritmos e ver quais é o servidor tem
        print(request.content)


    def send_message(self,message):
        """ Encodes messages """

        if self.shared_key:        
            message = self.encrypt_message(json.dumps(message).encode('latin'))            

        else:
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
    
    

    def dh_key_gen(self):
        """
        Generates the parameters necessary to start the Diffie-Hellman Algorithm
        along with the server private and public key.
        After that sends to client parameters and pub_key
        """
        logger.debug('Generating parameters and keys...')
        self.dh_parameters = dh.generate_parameters(generator=2, key_size=1024)
        self.private_key = self.dh_parameters.generate_private_key()
        self.public_key = self.private_key.public_key()
        parameter_num = self.dh_parameters.parameter_numbers()
        logger.debug('Generated keys and parameters with sucess')
        #print(parameter_num.g, parameter_num.p)
        pub_key=self.public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
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
        self.cipher = availableciphers[0]
        self.digest = availabledigests[0]
        self.mode   = availablemodes[0]
        print(self.cipher,self.digest,self.mode)
        logger.debug('Sucess checking ciphers')
        #enviar 
        message = {'method': 'NEGOTIATE_ALG','cipher':self.cipher,'mode':self.mode,'digest':self.digest}
        return self.send_message(message)
        
    
    def dh_exchange_key(self,request):
        data= json.loads(request.content.getvalue())
        method=data['method']
        if method =='KEY_EXCHANGE':
            logger.debug('Confirmed the exchange of a key')
            received_key=data['pub_key'].encode()
            self.client_pubkey=load_pem_public_key(received_key)
            self.shared_key = self.private_key.exchange(self.client_pubkey)
            message = {'method':'ACK'}
            return self.send_message(message)

        logger.debug('Could not exchange a key. oof')
        return self.send_error_message('NACK')
        

        
    def do_post_protocols(self,request):
        data = json.loads(request.content.getvalue())
        print(type(data))
        method=data['method']
        if method == 'NEGOTIATE_ALG':
            return self.negotiate_alg(data)
        elif method == 'DH_START':
            return self.key_exchange(data)

        


    
    # Handle a GET request
    def render_GET(self, request):
        logger.debug(f'Received request for {request.uri}')
        print(request.uri)

        try:
            if request.path == b'/api/protocols':
                return self.do_get_protocols(request)
            elif request.uri == b'/api/key':
            #...chave publica do server
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return self.dh_key_gen()
            #elif request.uri == 'api/auth':
            #autenticaçao, later on..
            elif request.path == b'/api/list':
                return self.do_list(request)

            elif request.path == b'/api/download':
                return self.do_download(request)
            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/protocols /api/list /api/download'

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
    