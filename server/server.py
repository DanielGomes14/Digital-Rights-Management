#!/usr/bin/env python

from twisted.web import server, resource
from twisted.internet import reactor, defer
from cryptography.hazmat.backends.interfaces import RSABackend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.hazmat.primitives import serialization  
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
        self.ciphermodes = ['CBC','GCM','ECB']
        self.public_key,self.private = self.keygen()

        
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
        return json.dumps(media_list, indent=4).encode('latin')


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

    def do_get_protocols(self,request):
        #receber os algoritmos e ver quais é o servidor tem
        print(request.content)


    def send_message(self,method):
        message = None
        if method == 'NEGOTIATE_ALG':
            data = {'method': 'ALG_OK','cipher':self.cipher,'mode':self.mode,'digest':self.digest}
            message = json.dumps(data).encode('latin')
        elif method == 'EXCHANGE_KEY':
            data= {'method': 'KEY_OK'}
            message = json.dumps(data).encode('latin')
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
    

    def keygen(self):
        """
        Generates a keypair using the cryptography lib and returns a tuple (public, private)
        """
        private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        public_key = private_key.public_key()
        
        
        #print(pem)
        return (public_key,private_key)

    def negotiate_alg(self,data):
        logger.debug('CHECKING CIPHERS')
        message=None
        client_ciphers,client_digests,client_ciphermodes=data['ciphers'],data['digests'],data['ciphermodes']
        availableciphers=[c for c in self.ciphers if c in client_ciphers]
        availabledigests=[c for c in  self.digests if c in client_digests]
        availablemodes=[c for c in self.ciphermodes if c in client_ciphermodes]
        if len(availableciphers)==0 or len(availabledigests) == 0  or len(availablemodes) == 0:
            logger.error('NO AVAILABLE CIPHERS,DIGESTs OR CIPHERMODES')
            message=self.send_error_message('NEGOTIATE_ALG')
        else:
            # enviar mensagem a dizer q n pode
            #server chooses the cipher to communicate acordding to client's available ciphers
            self.cipher = availableciphers[0]
            self.digest = availabledigests[0]
            self.mode   = availablemodes[0]
            print(self.cipher,self.digest,self.mode)
            logger.debug('Sucess checking ciphers')
            #enviar 
            message= self.send_message('NEGOTIATE_ALG')
        
        return message
    
    def key_exchange(self,data):
        
        if 'key' in data:
            # dar decrypt
            self.key = data['key']
            return self.send_message('EXCHANGE_KEY')     
        
        return self.send_error_message('EXCHANGE_KEY')
        

        
    def do_post_protocols(self,request):
        data = json.loads(request.content.getvalue())
        method=data['method']
        if method == 'NEGOTIATE_ALG':
            return self.negotiate_alg(data)
        elif method == 'EXCHANGE_KEY':
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
                pubkey=self.public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
                print(pubkey)
                return json.dumps({"KEY":pubkey}).encode("latin")
            #elif request.uri == 'api/auth':
            #autenticaçao, later on..
            elif request.path == b'/api/list':
                return self.do_list(request)

            elif request.path == b'/api/download':
                return self.do_download(request)
            else:
                print("fds")
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

                return self.do_post_protocols(request)

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
    