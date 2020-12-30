import binascii
import datetime
import json
import logging
import os
import subprocess
import sys
import time

import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from PyKCS11 import *
from cryptography.hazmat.primitives.serialization.base import Encoding
from cryptography.x509.oid import NameOID

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'

shared_key = None
matched_mode = None
matched_alg = None
matched_hash = None
current_derived_key = None
licence = None


def public_key_compose(p, g, y):
    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters(backend=default_backend())
    peer_public_numbers = dh.DHPublicNumbers(y, pn)
    return peer_public_numbers.public_key(backend=default_backend())


def public_key_decompose(pub):
    p = pub.public_numbers().parameter_numbers.p
    g = pub.public_numbers().parameter_numbers.g
    y = pub.public_numbers().y

    return p, g, y

#Generates client private key
def generate_private_key(parameters):
    """Generate private key"""
    return parameters.generate_private_key()

#Generates client private key
def generate_public_key(parameters, private_key):
    """Generate public key"""
    public_key = private_key.public_key()
    return public_key


def generate_public_and_private_keys():
    """Returns generated keys"""
    parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())
    privk = generate_private_key(parameters)
    pubk = generate_public_key(parameters, privk)
    return pubk, privk


def build(p, g, y):
    """Builds the key based on it's parameters (p,g,y)"""
    print('Building key... ')
    param_nums = dh.DHParameterNumbers(p, g)
    parameters = param_nums.parameters(backend=default_backend())
    pub_nums = dh.DHPublicNumbers(y, param_nums)
    return pub_nums.public_key(backend=default_backend())


def dismantle(pubk):
    """Dismantles the key and returns it's parameters (p,g,y)"""
    print('Decomposing key ', pubk)
    return pubk.public_numbers().parameter_numbers.p, pubk.public_numbers().parameter_numbers.g, pubk.public_numbers().y


def send_pubk(pubk):
    """Send public key to server"""

    #----/ Decompose Public Key /----#
    p, g, y = dismantle(pubk)

    #----/ Send public key to server /----#
    print("Sending... ")
    req = requests.get(f'{SERVER_URL}/api/key?p={p}&g={g}&y={y}')

    #----/ Error /----#
    if req.status_code != 200:
        print("Error. Public key not sent.")
        sys.exit(0)

    #----/ Sucess /----#
    print('Public key sent... Getting server public key...')
    server_params = json.loads(req.text)

    return server_params


def get_server_public_key(parameters):
    """Build server public key"""
    #----/ Build server key based on received parameters /----#
    server_pubk = build(parameters["p"], parameters["g"], parameters["y"])
    return server_pubk


def exchange_keys(privk, server_pubk):
    global matched_hash
    """Perform key exchange and key derivation"""
    #----/ Exchange keys /----#
    print("Creating shared key...")
    shared_key = privk.exchange(server_pubk)

    #----/ Key Derivation /----#
    derived = HKDF(algorithm=matched_hash, length=32, salt=None, info=b'handshake data',
                   backend=default_backend()).derive(shared_key)

    print("Derived key ", derived)
    return derived


def decryptChaCha20(derived_shared_key, nonce, msg):
    """CHACHA20 decrypting algorithm """
    global current_derived_key

    algorithm = algorithms.ChaCha20(current_derived_key, nonce)
    decryptor = Cipher(algorithm, None, default_backend()).decryptor()
    return decryptor.update(msg)


def encryptChaCha20(key, msg, nonce=None):
    """CHACHA20 encrypting algorithm """
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


def decryptAES(derived_shared_key, iv, msg):
    global matched_mode
    """AES decrypting algorithm """
    if matched_mode == "OFB":
        cipher = Cipher(algorithms.AES(derived_shared_key), modes.OFB(iv))
    if matched_mode == "CTR":
        cipher = Cipher(algorithms.AES(derived_shared_key), modes.CTR(iv))
    if matched_mode == "CFB":
        cipher = Cipher(algorithms.AES(derived_shared_key), modes.CFB(iv))

    decryptor = cipher.decryptor()
    return decryptor.update(msg) + decryptor.finalize()


def encryptAES(key, msg, iv=None):
    global matched_mode
    global shared_key
    """AES decrypting algorithm """
    if not iv:
        iv = os.urandom(16)

    if matched_mode == "OFB":
        cipher = Cipher(algorithms.AES(shared_key), modes.OFB(iv))
    if matched_mode == "CTR":
        cipher = Cipher(algorithms.AES(shared_key), modes.CTR(iv))
    if matched_mode == "CFB":
        cipher = Cipher(algorithms.AES(shared_key), modes.CFB(iv))

    encryptor = cipher.encryptor()
    ct = encryptor.update(bytes(msg, 'utf-8')) + encryptor.finalize()

    if shared_key == key:
        return ct

    return ct, iv


def derive_key(data=None):
    global shared_key
    global current_derived_key
    global matched_alg
    global matched_hash
    """Derives the shared key bettween the server and the client """
    current_derived_key = HKDF(algorithm=matched_hash,
                               length=32,
                               salt=None,
                               info=b'handshake data' if not data else bytes(str(data), 'utf-8'),
                               backend=default_backend()).derive(shared_key)

    return current_derived_key


def valid_cert_chain(chain, cert, roots):
    chain.append(cert)
    issuer = cert.issuer
    subject = cert.subject

    # Quando chegar à root (em self-signed certificates o issuer é igual ao subject)
    if issuer == subject and subject in roots:
        return True

    if issuer in roots:
        return valid_cert_chain(chain, roots[issuer], roots)

    print("Invalid Chain!")
    return False


def read_cc():
    try:
        lib = '/usr/local/lib/libpteidpkcs11.dylib'
        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load(lib)
        slots = pkcs11.getSlotList()
        if slots:
            slot = pkcs11.getSlotList(tokenPresent=True)[0]
            print("Valid CC")
            all_attr = list(PyKCS11.CKA.keys())
            all_attr = [e for e in all_attr if isinstance(e, int)]
            session = pkcs11.openSession(slot)
            userInfo = dict()
            for obj in session.findObjects():

                # Get object attributes
                attr = session.getAttributeValue(obj, all_attr)
                # Create dictionary with attributes
                attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))
                if attr['CKA_LABEL'] == 'CITIZEN AUTHENTICATION CERTIFICATE':
                    if attr['CKA_CERTIFICATE_TYPE'] != None:
                        cert = x509.load_der_x509_certificate(bytes(attr['CKA_VALUE']))

            private_key = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                                               (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]

            return {'cert': cert, 'private_key': private_key, 'session': session}
    except:
        print("Can't read CC")
        sys.exit()


def enc_json(json_dumps):
    derive_key()
    global matched_alg
    global current_derived_key
    global matched_mode

    if matched_alg == "AES":

        iv = os.urandom(16)

        if matched_mode == "OFB":
            cipher = Cipher(algorithms.AES(current_derived_key), modes.OFB(iv))
        if matched_mode == "CTR":
            cipher = Cipher(algorithms.AES(current_derived_key), modes.CTR(iv))
        if matched_mode == "CFB":
            cipher = Cipher(algorithms.AES(current_derived_key), modes.CFB(iv))

        encryptor = cipher.encryptor()
        ct = encryptor.update(bytes(json_dumps, 'utf-8')) + encryptor.finalize()
        return iv + ct

    if matched_alg == "CHACHA20":
        nonce = os.urandom(16)
        algorithm = algorithms.ChaCha20(current_derived_key, nonce)
        cipher = Cipher(algorithm, mode=None)
        encryptor = cipher.encryptor()
        ct = encryptor.update(bytes(json_dumps, 'utf-8'))

        return nonce + ct


def dec_json(enc_json):
    derive_key()
    global matched_alg
    global current_derived_key
    k = current_derived_key
    vec = enc_json[:16]
    msg = enc_json[16:]

    if matched_alg == "AES":
        if matched_mode == "OFB":
            cipher = Cipher(algorithms.AES(current_derived_key), modes.OFB(vec))
        if matched_mode == "CTR":
            cipher = Cipher(algorithms.AES(current_derived_key), modes.CTR(vec))
        if matched_mode == "CFB":
            cipher = Cipher(algorithms.AES(current_derived_key), modes.CFB(vec))

        decryptor = cipher.decryptor()
        return decryptor.update(msg) + decryptor.finalize()

    if matched_alg == "CHACHA20":
        algorithm = algorithms.ChaCha20(current_derived_key, vec)
        decryptor = Cipher(algorithm, None, default_backend()).decryptor()
        return decryptor.update(msg)


def main():
    global shared_key
    global matched_mode
    global matched_alg
    global matched_hash
    global licence
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    # Get a list of media files
    print("Contacting Server")

    print("##################################### CIPHER AGREEMENTS #####################################")
    ALGORITHMS = ['AES']
    MODE = ['CTR', 'CFB', 'OFB']
    HASH = ['SHA-256', 'SHA-512', 'MD5']

    req = requests.get(f'{SERVER_URL}/api/protocols?ALGORITHMS={ALGORITHMS}&Modes={MODE}&Digests={HASH}')

    if req.status_code != 200:
        print("Error. Couldn't agree on protocols")
        exit()

    args = json.loads(req.text)
    print("Request protocols: ", args)
    matched_alg = args["Algorithm"]
    matched_mode = args["Mode"]
    hash_agree = args["Hash"]
    if hash_agree == "SHA-256":
        matched_hash = hashes.SHA256()
    if hash_agree == "SHA-512":
        matched_hash = hashes.SHA512()
    if hash_agree == "MD5":
        matched_hash = hashes.MD5()

    print("###################################### LICENCE ##############################################")
    req = requests.get(f'{SERVER_URL}/api/licence')
    resp = json.loads(req.text)
    client_cert_bytes = binascii.a2b_base64(resp["certificate"].encode('latin'))
    licence = x509.load_der_x509_certificate(client_cert_bytes, backend=default_backend())
    print("Licence ", licence)

    print("##################################### DIFFIE-HELLMAN #######################################")

    #----/ Generate Client Keys /----#
    print('Generating keys...')
    pubk, privk = generate_public_and_private_keys()

    #----/ Send Public Key /----#
    print('Sending public key to server')
    server_params = send_pubk(pubk)

    #----/ Build Server Public Key based on response parameters /----#
    server_pubk = get_server_public_key(server_params)

    #----/ Perform key exchange and derivation /----#
    shared_key = exchange_keys(privk, server_pubk)

    print("################################# CERTIFICATE AUTHENTICATION ###############################")

    #----/ Server Authentication/----#
    req = requests.get(f'{SERVER_URL}/api/auth?opt={"get_cert"}')

    if req.status_code != 200:
        print("Error. Couldn't receive server certificate")
        sys.exit()

    server_cert = json.loads(dec_json(req.content))
    server_cert = server_cert['cert']
    server_cert = binascii.a2b_base64(server_cert.encode('latin'))
    server_cert = x509.load_pem_x509_certificate(server_cert)

    #----/ Get Root CA Certificate /----#
    with open("certs/Root_CA.pem", "rb") as cert_file:
        root_cert = cert_file.read()
        root_cert = x509.load_pem_x509_certificate(root_cert)

    #----/ Chain Validation /----#
    roots = {root_cert.issuer: root_cert}
    chain = []
    valid_chain = valid_cert_chain(chain, server_cert, roots)

    if not valid_chain:
        print("Invalid certificate chain!")
        sys.exit()

    #----/ Send Nonce /----#
    nonce = os.urandom(32)
    encoded_nonce = binascii.b2a_base64(nonce).decode('latin')

    send = enc_json(json.dumps({'nonce': encoded_nonce}))

    req = requests.post(f'{SERVER_URL}/api/auth', data=send)

    if req.status_code != 200:
        print("Error. Couldn't receive server nonce signature")
        sys.exit()

    #----/ Validate signature /----#
    server_signature = json.loads(dec_json(req.content))
    server_signature = server_signature['signature']
    server_signature = binascii.a2b_base64(server_signature.encode('latin'))

    server_cert_pubk = server_cert.public_key()
    try:
        server_cert_pubk.verify(server_signature, nonce,
                                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                hashes.SHA256())

    except InvalidSignature:
        print("Error. Invalid server signature!")
        sys.exit()

    print("################################# HARDWARE TOKEN AUTHENTICATION ###############################")

    cc_attrs = read_cc()

    cert_bytes = cc_attrs['cert'].public_bytes(Encoding.PEM)

    cert = enc_json(json.dumps({'cert': binascii.b2a_base64(cert_bytes).decode('latin').strip()}))

    req = requests.post(f'{SERVER_URL}/api/hardware_auth', data=cert)

    server_nonce = json.loads(dec_json(req.content))
    server_nonce = server_nonce['nonce'].strip()
    server_nonce = binascii.a2b_base64(server_nonce.encode('latin'))

    session = cc_attrs['session']

    mechanism = Mechanism(CKM_SHA1_RSA_PKCS, None)

    cc_cert = cc_attrs['cert']
    private_key = cc_attrs['private_key']

    signature = bytes(session.sign(private_key, server_nonce, mechanism))

    send = enc_json(json.dumps({'signature': binascii.b2a_base64(signature).decode('latin')}, indent=4))

    req = requests.post(f'{SERVER_URL}/api/validate_signature', data=send)

    if req.status_code != 200:
        print(f"Error. Invalid signature. Status code {req.status_code}")
        print(req.text)
        sys.exit()

    print("##################################### CHUNK PROCESSING #####################################")

    req = requests.get(f'{SERVER_URL}/api/list')
    if req.status_code == 200:
        print("Got Server List")

    media_list = json.loads(dec_json(req.content))

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
        chunk_id = chunk

        req = requests.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}')

        if req.status_code == 300:
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print("!!YOUR LICENSE HAS EXPIRED!!")
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            exit()

        chunk = json.loads(dec_json(req.content[256:]))

        #Server signature
        signature = req.content[:256]

        #Verify if is really is the server signature
        if server_cert_pubk.verify(signature, req.content[256:],
                                   padding.PSS(mgf=padding.MGF1(matched_hash), salt_length=padding.PSS.MAX_LENGTH),
                                   matched_hash) is not None:
            exit(1)

        # TODO: Process chunk

        derived_shared_key = derive_key(str(chunk_id) + media_item["id"])

        if matched_alg == "CHACHA20":
            derived_shared_key = derive_key(str(chunk_id) + media_item["id"])
            encrypted = binascii.a2b_base64(chunk['data'].encode('latin'))
            iv = binascii.a2b_base64(chunk['iv'].encode('latin'))
            json_nonce = binascii.a2b_base64(chunk['json_nonce'].encode('latin'))
            recv_hmac = binascii.a2b_base64(chunk['hmac'].encode('latin'))
            decrypted = binascii.a2b_base64(
                str(decryptChaCha20(derived_shared_key, iv, encrypted), 'utf-8').encode('latin'))

        if matched_alg == "AES":
            derived_shared_key = derive_key(str(chunk_id) + media_item["id"])
            encrypted = binascii.a2b_base64(chunk['data'].encode('latin'))
            iv = binascii.a2b_base64(chunk['iv'].encode('latin'))
            json_iv = binascii.a2b_base64(chunk['json_iv'].encode('latin'))
            recv_hmac = binascii.a2b_base64(chunk['hmac'].encode('latin'))
            decrypted = binascii.a2b_base64(str(decryptAES(derived_shared_key, iv, encrypted), 'utf-8').encode('latin'))

        h = hmac.HMAC(current_derived_key, matched_hash)
        h.update(encrypted)

        try:
            h.verify(bytes(recv_hmac))
        except:
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print("Chunk has been tampered with!")
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            break
        try:
            proc.stdin.write(decrypted)
        except:
            break


if __name__ == '__main__':
    while True:
        main()
        time.sleep(1)
