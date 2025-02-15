#!/usr/bin/env python

import ast
import binascii
import datetime
import glob
import json
import logging
import math
import os
import sys
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.interfaces import DHBackend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import dh, dsa, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_private_key
from cryptography.x509.oid import NameOID
from twisted.internet import defer, reactor
from twisted.web import resource, server

shared_key = None
mode = None
algorithm = None
hash_mode = None
current_derived_key = None
cert_privk = None
client_cert = None
auth_nonce = None
cc_cert = None


crl = []
intermediate_cc_certs = []
after_intermediate_cc_certs = []
ca_cc_certs = []
root_cc_certs = []

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

CATALOG = {
    '898a08080d1840793122b7e118b27a95d117ebce': {
        'name': 'Sunny Afternoon - Upbeat Ukulele Background Music',
        'album': 'Upbeat Ukulele Background Music',
        'description': 'Nicolai Heidlas Music: http://soundcloud.com/nicolai-heidlas',
        'duration': 3 * 60 + 33,
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
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return self.enc_json(json.dumps(media_list, indent=4))

    # Send a media chunk to the client
    def do_download(self, request):
        """ Sends the encrypted chunk with the signature"""
        global algorithm
        global shared_key
        global hash_mode
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
            if chunk_id >= 0 and chunk_id < math.ceil(media_item['file_size'] / CHUNK_SIZE):
                valid_chunk = True
        except:
            logger.warn("Chunk format is invalid")

        if not valid_chunk:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'invalid chunk id'}).encode('latin')

        logger.debug(f'Download: chunk: {chunk_id}')

        offset = chunk_id * CHUNK_SIZE + 16

        #Verify if the client still has a valid license
        with open("certs/Client_licence.pem", "rb") as f:
            pem_data = f.read()
            f.close()

        cli_license = x509.load_pem_x509_certificate(pem_data, default_backend())

        license_val = cli_license.not_valid_after
        now_date = datetime.datetime.now()
        if now_date > license_val:
            request.setResponseCode(300)
            return b''
        # Open file, seek to correct position and return the chunk
        with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
            iv_mp3 = f.read(16)
            f.seek(offset)

            with open("certs/mp3_key.txt", "rb") as f1:
                mp3_key = f1.read()
            data = b''
            while len(data) != CHUNK_SIZE:
                data_temp = f.read(16)
                cipher = Cipher(algorithms.AES(mp3_key), modes.OFB(iv_mp3))
                decryptor = cipher.decryptor()
                data += decryptor.update(data_temp) + decryptor.finalize()

            request.responseHeaders.addRawHeader(b"content-type", b"application/json")

            data = binascii.b2a_base64(data).decode('latin').strip()

            chunk_media_id = str(chunk_id) + media_id

            derived_shared_key = self.derive_key(chunk_media_id)
            print("derived_shared_key ", derived_shared_key)

            encrypted_chunk, iv = self.encrypt_chunk(derived_shared_key, data, chunk_media_id)
            hmac = self.generate_hmac(encrypted_chunk)

            if algorithm == "AES":
                json_iv = os.urandom(16)

                ret = self.enc_json(
                    json.dumps(
                        {
                            'media_id': media_id,
                            'chunk': chunk_id,
                            'data': binascii.b2a_base64(encrypted_chunk).decode('latin'),
                            'iv': binascii.b2a_base64(iv).decode('latin'),
                            'hmac': binascii.b2a_base64(hmac).decode('latin'),
                            'json_iv': binascii.b2a_base64(json_iv).decode('latin'),
                        },
                        indent=4))

            if algorithm == "CHACHA20":
                json_nonce = os.urandom(16)

                ret = self.enc_json(
                    json.dumps(
                        {
                            'media_id': media_id,
                            'chunk': chunk_id,
                            'data': binascii.b2a_base64(encrypted_chunk).decode('latin'),
                            'iv': binascii.b2a_base64(iv).decode('latin'),
                            'hmac': binascii.b2a_base64(hmac).decode('latin'),
                            'json_nonce': binascii.b2a_base64(json_nonce).decode('latin'),
                        },
                        indent=4))

            with open("certs/server_pk.pem", "rb") as key_file:
                private_key = serialization.load_pem_private_key(key_file.read(), None, backend=default_backend())

            if isinstance(private_key, rsa.RSAPrivateKey):
                signature = private_key.sign(
                    ret, padding.PSS(mgf=padding.MGF1(hash_mode), salt_length=padding.PSS.MAX_LENGTH), hash_mode)
            else:
                raise TypeError

            return signature + ret

        # File was not open?
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return self.enc_json(json.dumps({'error': 'unknown'}, indent=4))

    def do_get_protocols(self, request):
        """ Receives the client's chiper suite and finds compatible fields"""
        global mode
        global algorithm
        global hash_mode
        """Negotiation of the protocols with the client """
        ALGORITHMS = ['CHACHA20', 'AES']
        MODE = ['CFB', 'OFB', 'CTR']
        HASH = ['SHA-512', 'SHA-256', 'MD5']

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
        if matched_hash == "SHA-256":
            hash_mode = hashes.SHA256()
        elif matched_hash == "SHA-512":
            hash_mode = hashes.SHA512()
        elif matched_hash == "MD5":
            hash_mode = hashes.MD5()

        return json.dumps({
            "Algorithm": matched_alg,
            "Mode": matched_mode,
            "Hash": matched_hash
        }, indent=4).encode('latin')

    def do_get_licence(self, request):
        """Generates the license (ceritificate) and send it to the client """
        global hash_mode
        #get privk
        with open("certs/server_pk.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), None, backend=default_backend())
        #get pubk
        with open("certs/server_cert.crt", "rb") as cert_file:
            server_cert = x509.load_pem_x509_certificate(cert_file.read())
            server_cert_pubk = server_cert.public_key()

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"PT"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"AVEIRO"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"AVEIRO"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SIO"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"Client_licence"),
        ])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            server_cert_pubk).serial_number(x509.random_serial_number()).not_valid_before(
                datetime.datetime.utcnow()).not_valid_after(
                    # Our certificate will be valid for 10 minutes
                    datetime.datetime.utcnow() + datetime.timedelta(minutes=1)).add_extension(
                        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                        critical=False,
                        # Sign our certificate with our private key
                    ).sign(private_key, hash_mode)
        # Write our certificate out to disk.
        with open("certs/Client_licence.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        client_cert_bytes = cert.public_bytes(Encoding.DER)
        return json.dumps({
            'certificate': binascii.b2a_base64(client_cert_bytes).decode('latin').strip()
        }, indent=4).encode('latin')

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
                return self.enc_json(json.dumps({
                    'cert': binascii.b2a_base64(cert_file.read()).decode('latin').strip()
                }, indent=4))

    def sign_client_nonce(self, client_nonce):
        """Signs the client nonce"""
        global hash_mode
        with open("certs/server_pk.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), None, backend=default_backend())

        decoded_nonce = binascii.a2b_base64(client_nonce.encode('latin'))

        signature = private_key.sign(decoded_nonce,
                                     padding.PSS(mgf=padding.MGF1(hash_mode), salt_length=padding.PSS.MAX_LENGTH),
                                     hash_mode)

        return self.enc_json(json.dumps({'signature': binascii.b2a_base64(signature).decode('latin')}, indent=4))

    def generate_intermediate_cc_certs(self):
        """ Generates intermediate cc certs (first chain link) """
        global intermediate_cc_certs

        certs = glob.glob('./cc_certs/intermediates/*.cer')
        for cert in certs:
            with open(cert, 'rb') as cert_file:
                cert_file = cert_file.read()
                try:
                    cert = x509.load_pem_x509_certificate(cert_file)
                    intermediate_cc_certs.append(cert)
                except:
                    cert = x509.load_der_x509_certificate(cert_file)
                    intermediate_cc_certs.append(cert)

    def generate_after_intermediate_cc_certs(self):
        """ Generates after intermediate cc certs (second chain link) """

        global after_intermediate_cc_certs
        certs = glob.glob('cc_certs/cc/*.cer')
        for cert in certs:
            with open(cert, 'rb') as cert_file:
                cert_file = cert_file.read()
                try:
                    cert = x509.load_pem_x509_certificate(cert_file)
                    after_intermediate_cc_certs.append(cert)
                except:
                    cert = x509.load_der_x509_certificate(cert_file)
                    after_intermediate_cc_certs.append(cert)

    def generate_ca_cc_certs(self):
        """ Generates ca cc certs (third chain link) """
        global ca_cc_certs

        certs = glob.glob('cc_certs/CA/*.crt')
        for cert in certs:
            with open(cert, 'rb') as cert_file:
                cert_file = cert_file.read()
                try:
                    cert = x509.load_pem_x509_certificate(cert_file)
                    ca_cc_certs.append(cert)
                except:
                    cert = x509.load_der_x509_certificate(cert_file)
                    ca_cc_certs.append(cert)

    def generate_root_cc_certs(self):
        """ Generates root cc certs (fourth chain link) """
        global root_cc_certs

        certs = glob.glob('cc_certs/etc/ssl/certs/*')
        for cert in certs:

            try:
                with open(cert, 'rb') as cert_file:
                    cert_file = cert_file.read()
            except:
                continue
            try:
                cert = x509.load_pem_x509_certificate(cert_file)
                root_cc_certs.append(cert)
            except:
                cert = x509.load_der_x509_certificate(cert_file)
                root_cc_certs.append(cert)

    def generate_crl(self):
        """ Generate CRLs"""
        global crl

        certs = glob.glob('cc_certs/CRL/*.crl')
        for cert in certs:

            try:
                with open(cert, 'rb') as crl_file:
                    crl_file = crl_file.read()
            except:
                continue
            try:
                cert = x509.load_pem_x509_crl(crl_file)
                crl.append(cert)
            except:
                cert = x509.load_der_x509_crl(crl_file)
                crl.append(cert)

    def is_valid_certificate(self, issuer_cert):
        """ Checks if certificate is not expired and hasn't been revoked """
        global crl

        if datetime.datetime.now().timestamp() < issuer_cert.not_valid_before.timestamp() or datetime.datetime.now(
        ).timestamp() > issuer_cert.not_valid_after.timestamp():
            return False

        if issuer_cert in crl:
            return False

        return True

    def validate_cc_chain(self, cert):
        """ Validates the whole chain of a give certificate """
        # FALTA FAZER CRLS
        global intermediate_cc_certs
        global after_intermediate_cc_certs
        global ca_cc_certs
        global root_cc_certs
        global crl

        # 4838

        #[print(i) for i in root_cc_certs]

        if intermediate_cc_certs and after_intermediate_cc_certs and ca_cc_certs and root_cc_certs and crl:
            ret = True
        else:
            return False
        #----/ intermediate_cc_certs /----#
        for c in intermediate_cc_certs:
            if c.subject == cert.issuer:
                ret = True
                cert = c

                if not self.is_valid_certificate(cert):
                    return False

                #----/ after_intermediate_cc_certs /----#
                for c in after_intermediate_cc_certs:
                    if c.subject == cert.issuer:

                        ret = True
                        cert = c

                        if not self.is_valid_certificate(cert):
                            return False

                        #----/ ca_cc_certs /----#
                        for c in ca_cc_certs:
                            if c.subject == cert.issuer:
                                ret = True
                                cert = c

                                if not self.is_valid_certificate(cert):
                                    return False

                                #----/ root_cc_certs /----#
                                for c in root_cc_certs:
                                    if c.subject == cert.issuer:

                                        ret = True
                                        cert = c

                                        if not self.is_valid_certificate(cert):
                                            return False
                                        break
                                    else:
                                        ret = False
                                break
                            else:
                                ret = False
                        break
                    else:
                        ret = False
                break
            else:
                ret = False

        print("VALID CHAIN ", ret)
        return ret

    def dec_json(self, enc_json):
        """ Decrypts the encrypted json based on algorithm"""
        self.derive_key()
        global algorithm
        global current_derived_key
        global mode
        k = current_derived_key
        print("ENC KEY ", current_derived_key)

        vec = enc_json[:16]
        msg = enc_json[16:]

        if algorithm == "AES":
            if mode == "OFB":
                cipher = Cipher(algorithms.AES(current_derived_key), modes.OFB(vec))
            if mode == "CTR":
                cipher = Cipher(algorithms.AES(current_derived_key), modes.CTR(vec))
            if mode == "CFB":
                cipher = Cipher(algorithms.AES(current_derived_key), modes.CFB(vec))

            decryptor = cipher.decryptor()
            return decryptor.update(msg) + decryptor.finalize()

        if algorithm == "CHACHA20":
            algorithm = algorithms.ChaCha20(current_derived_key, vec)
            decryptor = Cipher(algorithm, None, default_backend()).decryptor()
            return decryptor.update(msg)

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
        return pubk.public_numbers().parameter_numbers.p, pubk.public_numbers(
        ).parameter_numbers.g, pubk.public_numbers().y

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
        return int(request.args[b'p'][0].decode('latin')), int(request.args[b'g'][0].decode('latin')), int(
            request.args[b'y'][0].decode('latin'))

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
        global current_derived_key
        global algorithm
        global hash_mode
        """Derives the shared key """
        current_derived_key = HKDF(algorithm=hash_mode,
                                   length=32,
                                   salt=None,
                                   info=b'handshake data' if not data else bytes(str(data), 'utf-8'),
                                   backend=default_backend()).derive(shared_key)

        return current_derived_key

    def encrypt_chunk(self, key, data, chunk_media_id):
        """Encrypts a chunk with specified algorithm """
        global algorithm
        if algorithm == "AES":
            encrypted_data, iv = self.encryptAES(key, data)
        if algorithm == "CHACHA20":
            encrypted_data, iv = self.encryptChaCha20(key, data)
        return encrypted_data, iv

    def encryptAES(self, key, msg, iv=None):
        """Encrypts with AES algorithm """
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
        encryptor = cipher.encryptor()
        ct = encryptor.update(bytes(msg, 'utf-8')) + encryptor.finalize()

        if key == shared_key:
            return ct

        return ct, iv

    def decryptAES(self, iv, key, msg, mode):
        """decrypts with AES algorithm """
        if mode == "OFB":
            cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
        if mode == "CTR":
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        if mode == "CFB":
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(msg) + decryptor.finalize()

    def generate_hmac(self, encrypted_cunk):
        """generates hmac for authentication"""
        global current_derived_key
        global hash_mode

        h = hmac.HMAC(current_derived_key, hash_mode)
        h.update(encrypted_cunk)
        return h.finalize()

    def decryptChaCha20(self, derived_shared_key, nonce, msg):
        """Encrypts with CHACHA20 algorithm """
        global current_derived_key

        algorithm = algorithms.ChaCha20(shared_key, nonce)
        decryptor = Cipher(algorithm, None, default_backend()).decryptor()
        return decryptor.update(msg)

    def encryptChaCha20(self, key, msg, nonce=None):
        """Dencrypts with chacha20 algorithm """
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

    def enc_json(self, json_dumps):
        """ Encrypts the json string before sending it """
        self.derive_key()
        global algorithm
        global current_derived_key
        global mode

        if algorithm == "AES":

            iv = os.urandom(16)

            if mode == "OFB":
                cipher = Cipher(algorithms.AES(current_derived_key), modes.OFB(iv))
            if mode == "CTR":
                cipher = Cipher(algorithms.AES(current_derived_key), modes.CTR(iv))
            if mode == "CFB":
                cipher = Cipher(algorithms.AES(current_derived_key), modes.CFB(iv))

            encryptor = cipher.encryptor()
            ct = encryptor.update(bytes(json_dumps, 'utf-8')) + encryptor.finalize()

            return iv + ct

        if algorithm == "CHACHA20":
            nonce = os.urandom(16)
            algorithm = algorithms.ChaCha20(current_derived_key, nonce)
            cipher = Cipher(algorithm, mode=None)
            encryptor = cipher.encryptor()
            ct = encryptor.update(bytes(json_dumps, 'utf-8'))

            return nonce + ct

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
            elif request.path == b'/api/licence':
                return self.do_get_licence(request)
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
            global cc_cert
            global auth_nonce
            if request.path == b'/api/auth':
                """ receive the client's nonce for the server to sign """
                self.derive_key()
                client_nonce = json.loads(self.dec_json(request.content.read()))
                client_nonce = client_nonce['nonce']
                return self.sign_client_nonce(client_nonce)

            if request.path == b'/api/hardware_auth':
                """ Receives the CC certificate, builds the collection of lists (chain) and validates the certificate's
                chain"""
                self.derive_key()

                cc_cert = json.loads(self.dec_json(request.content.read()))
                cc_cert = cc_cert['cert']
                cc_cert = binascii.a2b_base64(cc_cert.encode('latin'))
                cc_cert = x509.load_pem_x509_certificate(cc_cert)

                self.generate_intermediate_cc_certs()
                self.generate_after_intermediate_cc_certs()
                self.generate_ca_cc_certs()
                self.generate_root_cc_certs()
                self.generate_crl()

                valid_chain = self.validate_cc_chain(cc_cert)

                if not valid_chain:
                    print("Error. Certificate chain not valid!")
                    sys.exit()
                print("Valid Certificate Chain")
                #----/ Send Nonce /----#
                nonce = os.urandom(32)
                auth_nonce = nonce
                nonce = binascii.b2a_base64(nonce).decode('latin')
                return self.enc_json(json.dumps({'nonce': nonce}, indent=4))

            if request.path == b'/api/validate_signature':
                """ Validates the server's nonce that was signed by the client"""
                self.derive_key()

                #----/ Validate signature /----#
                signature = json.loads(self.dec_json(request.content.read()))
                signature = signature['signature']
                signature = binascii.a2b_base64(signature.encode('latin'))

                cc_publick_key = cc_cert.public_key()
                # find first public key and verify signature
                pubKey = cc_cert.public_key()

                result = pubKey.verify(signature, auth_nonce, padding.PKCS1v15(), hashes.SHA1())
                print("\nVerified:", result)

                if result == None:
                    request.setResponseCode(200)
                    return b''
                else:
                    request.setResponseCode(500)
                    request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
                    return b''

            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/protocols /api/list /api/download'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''


print("Server started")
print("URL is: http://IP:8080")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()
