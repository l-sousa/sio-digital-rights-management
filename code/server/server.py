#!/usr/bin/env python

from twisted.web import server, resource
from twisted.internet import reactor, defer
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.interfaces import DHBackend
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import serialization
import logging
import binascii
import json
import os
import math
import ast
from cryptography import x509
from cryptography.exceptions import InvalidSignature


shared_key = None
mode = None
algorithm = None
hash_mode = None
current_derived_key = None
cert_privk = None
client_cert = None
auth_nonce = None

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

CATALOG_BASE = 'server/catalog'
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
        global algorithm
        global shared_key
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

            data = binascii.b2a_base64(data).decode('latin').strip()

            chunk_media_id = str(chunk_id) + media_id

            derived_shared_key = self.derive_key(chunk_media_id)
            print("derived_shared_key ", derived_shared_key)

            encrypted_chunk, iv = self.encrypt_chunk(
                derived_shared_key, data, chunk_media_id)
            hmac = self.generate_hmac(encrypted_chunk)

            if algorithm == "AES":
                json_iv = os.urandom(16)

                ret = json.dumps(
                    {
                        binascii.b2a_base64(self.encryptAES(shared_key, 'media_id', json_iv)).decode('latin').strip(): media_id,
                        binascii.b2a_base64(self.encryptAES(shared_key, 'chunk', json_iv)).decode('latin').strip(): chunk_id,
                        binascii.b2a_base64(self.encryptAES(shared_key, 'data', json_iv)).decode('latin').strip(): binascii.b2a_base64(encrypted_chunk).decode('latin'),
                        binascii.b2a_base64(self.encryptAES(shared_key, 'iv', json_iv)).decode('latin').strip(): binascii.b2a_base64(iv).decode('latin'),
                        binascii.b2a_base64(self.encryptAES(shared_key, 'hmac', json_iv)).decode('latin').strip(): binascii.b2a_base64(hmac).decode('latin'),
                        'json_iv': binascii.b2a_base64(json_iv).decode('latin'),
                    }, indent=4
                ).encode('latin')

            if algorithm == "CHACHA20":
                json_nonce = os.urandom(16)
                print("json nonce <><< ", json_nonce)
                ret = json.dumps(
                    {
                        binascii.b2a_base64(self.encryptChaCha20(shared_key, 'media_id', json_nonce)).decode('latin').strip(): media_id,
                        binascii.b2a_base64(self.encryptChaCha20(shared_key, 'chunk', json_nonce)).decode('latin').strip(): chunk_id,
                        binascii.b2a_base64(self.encryptChaCha20(shared_key, 'data', json_nonce)).decode('latin').strip(): binascii.b2a_base64(encrypted_chunk).decode('latin'),
                        binascii.b2a_base64(self.encryptChaCha20(shared_key, 'iv', json_nonce)).decode('latin').strip(): binascii.b2a_base64(iv).decode('latin'),
                        binascii.b2a_base64(self.encryptChaCha20(shared_key, 'hmac', json_nonce)).decode('latin').strip(): binascii.b2a_base64(hmac).decode('latin'),
                        'json_nonce': binascii.b2a_base64(json_nonce).decode('latin'),
                    }, indent=4
                ).encode('latin')

            return ret

        # File was not open?
        request.responseHeaders.addRawHeader(
            b"content-type", b"application/json")
        return json.dumps({'error': 'unknown'}, indent=4).encode('latin')

    def do_get_protocols(self, request):
        global mode
        global algorithm
        global hash_mode

        ALGORITHMS = ['CHACHA20']
        MODE = ['CFB']
        HASH = ['SHA-256', 'SHA-512', 'MD5', 'BLAKE2b']

        cli_alg = request.args[b'ALGORITHMS']
        cli_alg_d = cli_alg[0].decode('latin')
        cli_algs = cli_alg_d.strip('][').replace("'", "").split(', ')
        cli_mode = request.args[b'Modes']
        cli_mode_d = cli_mode[0].decode('latin')
        cli_mods = cli_mode_d.strip('][').replace("'", "").split(', ')
        cli_hash = request.args[b'Digests']
        cli_hash_d = cli_hash[0].decode('latin')
        cli_hashs = cli_hash_d.strip('][').replace("'", "").split(', ')

        matched_alg = None
        matched_mode = None
        matched_hash = None
        for alg in cli_algs:
            if alg in ALGORITHMS:
                matched_alg = alg
                break

        if matched_alg is None:
            request.setResponseCode(500)
            return b''

        for mod in cli_mods:
            if mod in MODE:
                matched_mode = mod
                break

        if matched_mode is None:
            request.setResponseCode(500)
            return b''

        for h in cli_hashs:
            if h in HASH:
                matched_hash = h
                break

        if matched_hash is None:
            request.setResponseCode(500)
            return b''

        mode = matched_mode
        algorithm = matched_alg
        hash_mode = matched_hash

        return json.dumps({"Algorithm": matched_alg, "Mode": matched_mode, "Hash": matched_hash}, indent=4).encode('latin')

    def do_get_public_key(self, request):
        """Receives the client's public key and sends server public key"""
        global shared_key
        #----/ Get client's public key parameters /----#
        p, g, y = self.get_parameters(request)

        #----/ Build client public key based on received parameters /----#
        client_pubk = self.get_client_public_key(p, g, y)

        #----/ Returns generated keys with same parameters as the client /----#
        print('Generating server keys...')
        pubk, privk = self.generate_public_and_private_keys(request)

        #----/ Perform key exchange and derivation /----#
        shared_key = self.exchange_keys(privk, client_pubk)

        #----/ Dismantle parameters to send to client /----#
        p, g, y = self.dismantle(pubk)

        print("Sending key to client...")
        return json.dumps({"p": p, "g": g, "y": y}, indent=4).encode('latin')

    def do_authenticate(self, request):
        global cert_privk
        #----/ Load server certificate /----#
        if request.args[b'opt'][0].decode('latin') == "get_cert":
            with open("certs/server_cert.crt", "rb") as cert_file:
                return json.dumps({
                    'cert': binascii.b2a_base64(cert_file.read()).decode('latin').strip()
                }, indent=4).encode('latin')

    def sign_client_nonce(self, client_nonce):
        with open("certs/server_pk.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), None, backend=default_backend())

        decoded_nonce = binascii.a2b_base64(client_nonce.encode('latin'))

        signature = private_key.sign(
            decoded_nonce,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()
        )

        # with open("../certs/server_cert.crt", "rb") as cert_file:
        #     server_cert = x509.load_pem_x509_certificate(cert_file.read())
        #     server_cert_pubk = server_cert.public_key()

        # #server_cert_pubk.verify(signature, decoded_nonce, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

        return json.dumps({
            'signature': binascii.b2a_base64(signature).decode('latin')
        }, indent=4).encode('latin')

    def valid_cert_chain(self, chain, cert, roots):
        chain.append(cert)
        issuer = cert.issuer
        subject = cert.subject

        # Quando chegar à root (em self-signed certificates o issuer é igual ao subject)
        if issuer == subject and subject in roots:
            return True

        if issuer in roots:
            return self.valid_cert_chain(chain, roots[issuer], roots)

        print("Invalid Chain!")
        return False

    # Handle a GET request

    def render_GET(self, request):
        logger.debug(f'Received request for {request.uri}')
        try:
            if request.path == b'/api/protocols':
                return self.do_get_protocols(request)
            elif request.path == b'/api/key':
                return self.do_get_public_key(request)
            elif request.path == b'/api/auth':
                return self.do_authenticate(request)
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

        try:
            global client_cert
            global auth_nonce
            if request.path == b'/api/auth':
                client_nonce = json.loads(request.content.read())
                client_nonce = client_nonce['nonce']
                return self.sign_client_nonce(client_nonce)

            if request.path == b'/api/client_cert':
                client_cert = json.loads(request.content.read())
                client_cert = client_cert['cert']
                client_cert = binascii.a2b_base64(client_cert.encode('latin'))
                client_cert = x509.load_pem_x509_certificate(client_cert)
                chain = []

                #----/ Get Root CA Certificate /----#
                with open("certs/Root_CA.pem", "rb") as cert_file:
                    root_cert = cert_file.read()
                    root_cert = x509.load_pem_x509_certificate(root_cert)

                roots = {root_cert.issuer: root_cert}

                validate_cert = self.valid_cert_chain(
                    chain, client_cert, roots)

                if not validate_cert:
                    print("Error. Certificate chain not valid!")
                    exit()

                #----/ Send Nonce /----#
                nonce = os.urandom(32)
                auth_nonce = nonce
                nonce = binascii.b2a_base64(nonce).decode('latin')
                return json.dumps({'nonce': nonce}, indent=4).encode('latin')

            if request.path == b'/api/validate_signature':
                #----/ Validate signature /----#
                signature = json.loads(request.content.read())
                signature = signature['signature']
                signature = binascii.a2b_base64(signature.encode('latin'))

                client_cert_pubk = client_cert.public_key()

                try:
                    client_cert_pubk.verify(signature, auth_nonce, padding.PSS(mgf=padding.MGF1(
                        hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                    request.setResponseCode(200)
                    return b''

                except InvalidSignature:
                    print("Error. Invalid server signature!")
                    exit()

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
        pubk = privk.public_key()
        return pubk, privk

    def get_parameters(self, request):
        """Get parameters of request"""
        return int(request.args[b'p'][0].decode('latin')), int(request.args[b'g'][0].decode('latin')), int(request.args[b'y'][0].decode('latin'))

    def exchange_keys(self, privk, client_pubk):
        """Perform key exchange and key derivation"""
        global shared_key
        #----/ Exchange keys /----#
        print("Creating shared key...")
        shared_key = privk.exchange(client_pubk)

        #----/ Key Derivation /----#
        derived = self.derive_key()

        print("Derived key ", derived)
        return derived

    def derive_key(self, data=None):
        global shared_key
        print("DATA>>>>>> ", data)
        global current_derived_key
        global algorithm

        current_derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data' if not data else bytes(str(data), 'utf-8'),
            backend=default_backend()
        ).derive(shared_key)

        return current_derived_key

    def encrypt_chunk(self, key, data, chunk_media_id):
        global algorithm
        if algorithm == "AES":
            encrypted_data, iv = self.encryptAES(key, data)
        if algorithm == "CHACHA20":
            encrypted_data, iv = self.encryptChaCha20(key, data)
        return encrypted_data, iv

    def encryptAES(self, key, msg, iv=None):
        global mode
        global shared_key

        if not iv:
            iv = os.urandom(16)

        if mode == "OFB":
            cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
        if mode == "CTR":
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        if mode == "CFB":
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        if mode == "CBC":
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(bytes(msg, 'utf-8')) + encryptor.finalize()

        if key == shared_key:
            return ct

        return ct, iv

    def decryptAES(self, iv, key, msg, mode):
        if mode == "OFB":
            cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
        if mode == "CTR":
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        if mode == "CFB":
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        if mode == "CBC":
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(msg) + decryptor.finalize()

    def generate_hmac(self, encrypted_cunk):
        global current_derived_key
        h = hmac.HMAC(current_derived_key, hashes.SHA256())
        h.update(encrypted_cunk)
        return h.finalize()

    def decryptChaCha20(self, derived_shared_key, nonce, msg):
        global current_derived_key

        algorithm = algorithms.ChaCha20(shared_key, nonce)
        decryptor = Cipher(algorithm, None, default_backend()).decryptor()
        return decryptor.update(msg)

    def encryptChaCha20(self, key, msg, nonce=None):
        global shared_key
        if not nonce:
            nonce = os.urandom(16)
        algorithm = algorithms.ChaCha20(key, nonce)
        cipher = Cipher(algorithm, mode=None)
        encryptor = cipher.encryptor()
        ct = encryptor.update(bytes(msg, 'utf-8'))

        if key == shared_key:
            return ct

        return ct, nonce


print("Server started")
print("URL is: http://IP:8080")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()
