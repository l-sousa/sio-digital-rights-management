from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac
import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'

ALGORITHMS = ['AES', 'Camellia']
MODE = ['CTR', 'GCM']
HASH = ['SHA-256', 'SHA-512', 'MD5', 'BLAKE2b']
shared_key = None
matched_mode = None
matched_algo = None
matched_hash = None
current_derived_key = None

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


def generate_private_key(parameters):
    """Generate private key"""
    return parameters.generate_private_key()


def generate_public_key(parameters, private_key):
    """Generate public key"""
    public_key = private_key.public_key()
    return public_key


def generate_public_and_private_keys():
    """Returns generated keys"""
    parameters = dh.generate_parameters(
        generator=2, key_size=512, backend=default_backend())
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
    """Perform key exchange and key derivation"""
    #----/ Exchange keys /----#
    print("Creating shared key...")
    shared_key = privk.exchange(server_pubk)

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


def decryptCamellia(derived_shared_key,iv, msg):
    global matched_mode

    if matched_mode == "OFB":
        cipher = Cipher(algorithms.Camellia(derived_shared_key), modes.OFB(iv))
    if matched_mode == "CTR":
        cipher = Cipher(algorithms.Camellia(derived_shared_key), modes.CTR(iv))
    if matched_mode == "CFB":
        cipher = Cipher(algorithms.Camellia(derived_shared_key), modes.CFB(iv))

    decryptor = cipher.decryptor()
    return decryptor.update(msg) + decryptor.finalize()


def encryptCamellia(self, key, msg):
    global matched_mode
    global shared_key
    iv = os.urandom(16)

    if matched_mode == "OFB":
        cipher = Cipher(algorithms.Camellia(shared_key), modes.OFB(iv))
    if matched_mode == "CTR":
        cipher = Cipher(algorithms.Camellia(shared_key), modes.CTR(iv))
    if matched_mode == "CFB":
        cipher = Cipher(algorithms.Camellia(shared_key), modes.CFB(iv))

    encryptor = cipher.encryptor()
    ct = encryptor.update(bytes(msg, 'utf-8')) + encryptor.finalize()

    return ct, iv

def decryptAES(derived_shared_key,iv, msg):
    global matched_mode

    if matched_mode == "OFB":
        cipher = Cipher(algorithms.AES(derived_shared_key), modes.OFB(iv))
    if matched_mode == "CTR":
        cipher = Cipher(algorithms.AES(derived_shared_key), modes.CTR(iv))
    if matched_mode == "CFB":
        cipher = Cipher(algorithms.AES(derived_shared_key), modes.CFB(iv))

    decryptor = cipher.decryptor()
    return decryptor.update(msg) + decryptor.finalize()


def encryptAES(self, key, msg):
    global matched_mode
    global shared_key
    iv = os.urandom(16)

    if matched_mode == "OFB":
        cipher = Cipher(algorithms.AES(shared_key), modes.OFB(iv))
    if matched_mode == "CTR":
        cipher = Cipher(algorithms.AES(shared_key), modes.CTR(iv))
    if matched_mode == "CFB":
        cipher = Cipher(algorithms.AES(shared_key), modes.CFB(iv))

    encryptor = cipher.encryptor()
    ct = encryptor.update(bytes(msg, 'utf-8')) + encryptor.finalize()

    return ct, iv

def derive_key(data=None):
        global shared_key
        global current_derived_key
        current_derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data' if not data else bytes(str(data), 'utf-8'),
            backend=default_backend()
        ).derive(shared_key)
        return current_derived_key

def main():
    global shared_key
    global matched_mode
    global matched_algo
    global matched_hash
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    # Get a list of media files
    print("Contacting Server")

    print("##################################### CIPHER AGREEMENTS #####################################")
    ALGORITHMS = ['AES', 'CHACHA20']
    MODE = ['CTR', 'GCM']
    HASH = ['SHA-256', 'SHA-512', 'MD5', 'BLAKE2b']

    req = requests.get(
        f'{SERVER_URL}/api/protocols?ALGORITHMS={ALGORITHMS}&Modes={MODE}&Digests={HASH}')
    if req.status_code != 200:
        print("Error. Couldn't agree on protocols")

    print("Request protocols: ", req.text)
    args = json.loads(req.text)
    matched_algo = args["Algorithm"]
    matched_mode = args["Mode"]
    matched_hash = args["Hash"]

    print("##################################### DIFFIE-HELLMAN #####################################")

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

    print("##################################### CHUNK PROCESSING #####################################")

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
        proc = subprocess.Popen(
            ['ffplay.exe', '-i', '-'], stdin=subprocess.PIPE)
    else:
        proc = subprocess.Popen(['ffplay', '-i', '-'], stdin=subprocess.PIPE)


    # Get data from server and send it to the ffplay stdin through a pipe
    for chunk in range(media_item['chunks'] + 1):
        chunk_id = chunk
        req = requests.get(
            f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}')
        chunk = req.json()

        # TODO: Process chunk

        derived_shared_key = derive_key(str(chunk_id) + media_item["id"])
        encrypted = binascii.a2b_base64(chunk['data'].encode('latin'))
        iv = binascii.a2b_base64(chunk['iv'].encode('latin'))
        matched_alg="Camellia"
        if matched_alg == "Camellia":
            decrypted = binascii.a2b_base64(str(decryptCamellia(derived_shared_key, iv, encrypted), 'utf-8').encode('latin'))
        if matched_alg == "AES":
            decrypted = binascii.a2b_base64(str(decryptAES(derived_shared_key, iv, encrypted), 'utf-8').encode('latin'))
        
        recv_hmac = binascii.a2b_base64(chunk['hmac'].encode('latin'))

        h = hmac.HMAC(current_derived_key, hashes.SHA256())
        h.update(encrypted)

        try:
            h.verify(bytes(recv_hmac))
        except: 
            print("Chunk has been tampered with!")
            break

        try:
            proc.stdin.write(decrypted)
        except:
            break


if __name__ == '__main__':
    while True:
        main()
        time.sleep(1)
