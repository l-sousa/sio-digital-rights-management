#!/usr/bin/env python
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from twisted.web import server, resource
from twisted.internet import reactor, defer
import logging
import binascii
import json
import os
import math

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

CATALOG = {'898a08080d1840793122b7e118b27a95d117ebce':
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

    # Send the list of media files to clients
    def do_list(self, request):

        #auth = request.getHeader('Authorization')
        # if not auth:
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
        request.responseHeaders.addRawHeader(
            b"content-type", b"application/json")
        return json.dumps(media_list, indent=4).encode('latin')

    # Send a media chunk to the client

    def do_download(self, request):
        logger.debug(f'Download: args: {request.args}')

        media_id = request.args.get(b'id', [None])[0]
        logger.debug(f'Download: id: {media_id}')

        # Check if the media_id is not None as it is required
        if media_id is None:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(
                b"content-type", b"application/json")
            return json.dumps({'error': 'invalid media id'}).encode('latin')

        # Convert bytes to str
        media_id = media_id.decode('latin')

        # Search media_id in the catalog
        if media_id not in CATALOG:
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(
                b"content-type", b"application/json")
            return json.dumps({'error': 'media file not found'}).encode('latin')

        # Get the media item
        media_item = CATALOG[media_id]

        # Check if a chunk is valid
        chunk_id = request.args.get(b'chunk', [b'0'])[0]
        valid_chunk = False
        try:
            chunk_id = int(chunk_id.decode('latin'))
            if chunk_id >= 0 and chunk_id < math.ceil(media_item['file_size'] / CHUNK_SIZE):
                valid_chunk = True
        except:
            logger.warn("Chunk format is invalid")

        if not valid_chunk:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(
                b"content-type", b"application/json")
            return json.dumps({'error': 'invalid chunk id'}).encode('latin')

        logger.debug(f'Download: chunk: {chunk_id}')

        offset = chunk_id * CHUNK_SIZE

        # Open file, seek to correct position and return the chunk
        with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
            f.seek(offset)
            data = f.read(CHUNK_SIZE)

            request.responseHeaders.addRawHeader(
                b"content-type", b"application/json")
            return json.dumps(
                {
                    'media_id': media_id,
                    'chunk': chunk_id,
                    'data': binascii.b2a_base64(data).decode('latin').strip()
                }, indent=4
            ).encode('latin')

        # File was not open?
        request.responseHeaders.addRawHeader(
            b"content-type", b"application/json")
        return json.dumps({'error': 'unknown'}, indent=4).encode('latin')

    def do_get_protocols(self, request):
        ALGORITHMS = ['AES', 'CHACHA20']
        MODE = ['CBC', 'GCM']
        HASH = ['SHA-256', 'SHA-512', 'MD5', 'BLAKE2b']

        cli_alg = request.args[b'algorithms']
        cli_alg_d = cli_alg[0].decode('latin')
        cli_algs = cli_alg_d.strip('][').replace("'", "").split(', ')
        cli_mode = request.args[b'mode']
        cli_mode_d = cli_mode[0].decode('latin')
        cli_mods = cli_mode_d.strip('][').replace("'", "").split(', ')
        cli_hash = request.args[b'hash']
        cli_hash_d = cli_hash[0].decode('latin')
        cli_hashs = cli_hash_d.strip('][').replace("'", "").split(', ')

        matched_alg = None
        matched_mode = None
        matched_hash = None
        for alg in cli_algs:
            if alg in ALGORITHMS:
                matched_alg = alg

        if matched_alg is None:
            request.setResponseCode(500)
            return b''

        for mod in cli_mods:
            if mod in MODE:
                matched_mode = mod

        if matched_mode is None:
            request.setResponseCode(500)
            return b''

        for h in cli_hashs:
            if h in HASH:
                matched_hash = h

        if matched_hash is None:
            request.setResponseCode(500)
            return b''

        return json.dumps({"Algorithm": matched_alg, "Mode": matched_mode, "Hash:": matched_hash}, indent=4).encode('latin')

    def build(self, p, g, y):
        """Builds the key based on it's parameters (p,g,y)"""
        print('Building key... ')
        param_nums = dh.DHParameterNumbers(p, g)
        parameters = param_nums.parameters(backend=default_backend())
        pub_nums = dh.DHPublicNumbers(y, param_nums)
        return pub_nums.public_key(backend=default_backend())

    def dismantle(self, pubk):
        """Dismantles the key and returns it's parameters (p,g,y)"""
        print('Decomposing key ', pubk)
        return pubk.public_numbers().parameter_numbers.p, pubk.public_numbers().parameter_numbers.g, pubk.public_numbers().y

    def get_client_public_key(self, p, g, y):
        """Build client public key based on received parameters"""
        print("Building client's public key...")
        client_pubk = self.build(p, g, y)
        return client_pubk

    def generate_private_key(self, parameters):
        """Generate private key"""
        return parameters.generate_private_key()

    def generate_public_key(self, parameters, private_key):
        """Generate public key"""
        public_key = private_key.public_key()
        return public_key

    def generate_public_and_private_keys(self, parameters):
        """Returns generated keys with same parameters as the client"""
        p, g, y = self.get_parameters(parameters)

        param_nums = dh.DHParameterNumbers(p, g)
        parameters = param_nums.parameters()
        privk = parameters.generate_private_key()
        pubk = pubk.public_key()
        return pubk, privk

    def get_parameters(self, request):
        """Get parameters of request"""
        return int(request.args[b'p'][0].decode('latin')), int(request.args[b'g'][0].decode('latin')), int(request.args[b'y'][0].decode('latin'))


def exchange_keys(slef, privk, client_pubk):
    """Perform key exchange and key derivation"""
    #----/ Exchange keys /----#
    print("Creating shared key...")
    shared_key = privk.exchange(client_pubk)

    #----/ Key Derivation /----#
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)

    print("Derived key ", derived)
    return derived

    def do_get_public_key(self, request):
        """Receives the client's public key and sends server public key"""

        #----/ Get client's public key parameters /----#
        p, g, y = self.get_parameters(request)

        #----/ Build client public key based on received parameters /----#
        client_pubk = self.get_client_public_key(p, g, y)

        #----/ Returns generated keys with same parameters as the client /----#
        print('Generating server keys...')
        pubk, privk = self.generate_public_and_private_keys(request)

        #----/ Perform key exchange and derivation /----#
        derived_key = exchange_keys(privk, client_pubk)

        #----/ Dismantle parameters to send to client /----#
        p, g, y = self.dismantle(pubk)

        print("Sending key to client...")
        return json.dumps({"p": p, "g": g, "y": y}, indent=4).encode('latin')

    # Handle a GET request
    def render_GET(self, request):
        logger.debug(f'Received request for {request.uri}')

        try:
            if request.path == b'/api/protocols':
                return self.do_get_protocols(request)
            elif request.path == b'/api/pubk':
                return self.do_get_public_key(request)
            # ...
            # elif request.uri == 'api/auth':

            elif request.path == b'/api/list':
                return self.do_list(request)

            elif request.path == b'/api/download':
                return self.do_download(request)
            else:
                request.responseHeaders.addRawHeader(
                    b"content-type", b'text/plain')
                return b'Methods: /api/protocols /api/list /api/download'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(
                b"content-type", b"text/plain")
            return b''

    # Handle a POST request
    def render_POST(self, request):
        logger.debug(f'Received POST for {request.uri}')
        request.setResponseCode(501)
        return b''


print("Server started")
print("URL is: http://IP:8080")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()
