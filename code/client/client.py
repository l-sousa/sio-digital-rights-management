from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import serialization
import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys
import datetime
from cryptography.exceptions import InvalidSignature

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


def decryptChaCha20(derived_shared_key, nonce, msg):
    global current_derived_key

    algorithm = algorithms.ChaCha20(current_derived_key, nonce)
    decryptor = Cipher(algorithm, None, default_backend()).decryptor()
    return decryptor.update(msg)


def encryptChaCha20(key, msg, nonce=None):
    global shared_key
    print("dentro do chacha -------------")

    if not nonce:
        nonce = os.urandom(16)
        print(len(nonce))
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()
    ct = encryptor.update(bytes(msg, 'utf-8'))

    if key == shared_key:
        return ct

    return ct, nonce


def decryptAES(derived_shared_key, iv, msg):
    global matched_mode

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

    current_derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data' if not data else bytes(str(data), 'utf-8'),
        backend=default_backend()
    ).derive(shared_key)

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


def sign_client_nonce(client_nonce):
    with open("certs/client_pk.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), None, backend=default_backend())

    decoded_nonce = binascii.a2b_base64(client_nonce.encode('latin'))

    signature = private_key.sign(
        decoded_nonce,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()
    )

    # with open("certs/client.crt", "rb") as cert_file:
    #         server_cert = x509.load_pem_x509_certificate(cert_file.read())
    #         server_cert_pubk = server_cert.public_key()

    # server_cert_pubk.verify(signature, decoded_nonce, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    return json.dumps({
        'signature': binascii.b2a_base64(signature).decode('latin')
    }, indent=4).encode('latin')


def main():
    global shared_key
    global matched_mode
    global matched_alg
    global matched_hash
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    # Get a list of media files
    print("Contacting Server")

    print("##################################### CIPHER AGREEMENTS #####################################")
    ALGORITHMS = ['CHACHA20', 'AES']
    MODE = ['CFB', 'GCM']
    HASH = ['SHA-256', 'SHA-512', 'MD5', 'BLAKE2b']

    req = requests.get(
        f'{SERVER_URL}/api/protocols?ALGORITHMS={ALGORITHMS}&Modes={MODE}&Digests={HASH}')

    if req.status_code != 200:
        print("Error. Couldn't agree on protocols")
        exit()

    print("Request protocols: ", req.text)
    args = json.loads(req.text)
    matched_alg = args["Algorithm"]
    matched_mode = args["Mode"]
    matched_hash = args["Hash"]

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
        exit()

    server_cert = req.json()
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
        exit()

    #----/ Send Nonce /----#
    nonce = os.urandom(32)
    encoded_nonce = binascii.b2a_base64(nonce).decode('latin')

    # Tentativa de post NÃO APAGAR
    # req = requests.post(f'{SERVER_URL}/api/auth?opt={"nonce"}', {'nonce': nonce})

    req = requests.post(f'{SERVER_URL}/api/auth',
                        data=json.dumps({'nonce': encoded_nonce}))

    if req.status_code != 200:
        print("Error. Couldn't receive server nonce signature")
        exit()

    #----/ Validate signature /----#
    server_signature = json.loads(req.text)
    server_signature = server_signature['signature']
    server_signature = binascii.a2b_base64(server_signature.encode('latin'))

    server_cert_pubk = server_cert.public_key()

    try:
        server_cert_pubk.verify(server_signature, nonce, padding.PSS(mgf=padding.MGF1(
            hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    except InvalidSignature:
        print("Error. Invalid server signature!")
        exit()

    #----/ Client Authentication /----#

    with open("certs/client_cert.crt", "rb") as cert_file:
        cert = json.dumps({
            'cert': binascii.b2a_base64(cert_file.read()).decode('latin').strip()
        }, indent=4).encode('latin')

    req = requests.post(f'{SERVER_URL}/api/client_cert',
                        data=cert)

    server_nonce = json.loads(req.text)
    server_nonce = server_nonce['nonce']
    signature = sign_client_nonce(server_nonce)

    req = requests.post(f'{SERVER_URL}/api/validate_signature',
                        data=signature)

    if req.status_code != 200:
        print("Error. Invalid signature")
        exit()

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

        if matched_alg == "CHACHA20":
            json_nonce = binascii.a2b_base64(
                chunk['json_nonce'].encode('latin'))
            print(type(json_nonce))
            encrypted = binascii.a2b_base64(chunk[binascii.b2a_base64(encryptChaCha20(
                shared_key, 'data', json_nonce)).decode('latin').strip()].encode('latin'))
            iv = binascii.a2b_base64(chunk[binascii.b2a_base64(encryptChaCha20(
                shared_key, 'iv', json_nonce)).decode('latin').strip()].encode('latin'))
            decrypted = binascii.a2b_base64(str(decryptChaCha20(
                derived_shared_key, iv, encrypted), 'utf-8').encode('latin'))

            recv_hmac = binascii.a2b_base64(chunk[binascii.b2a_base64(encryptChaCha20(
                shared_key, 'hmac', json_nonce)).decode('latin').strip()].encode('latin'))
        if matched_alg == "AES":
            json_iv = binascii.a2b_base64(chunk['json_iv'].encode('latin'))
            encrypted = binascii.a2b_base64(chunk[binascii.b2a_base64(encryptAES(
                shared_key, 'data', json_iv)).decode('latin').strip()].encode('latin'))
            iv = binascii.a2b_base64(chunk[binascii.b2a_base64(encryptAES(
                shared_key, 'iv', json_iv)).decode('latin').strip()].encode('latin'))
            decrypted = binascii.a2b_base64(
                str(decryptAES(derived_shared_key, iv, encrypted), 'utf-8').encode('latin'))

            recv_hmac = binascii.a2b_base64(chunk[binascii.b2a_base64(encryptAES(
                shared_key, 'hmac', json_iv)).decode('latin').strip()].encode('latin'))

        h = hmac.HMAC(current_derived_key, hashes.SHA256())
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
