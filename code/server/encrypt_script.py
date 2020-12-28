from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

pk = os.urandom(32)
iv = os.urandom(16)

with open("server/mp3_key.txt","wb+") as file:
    file.write(pk)
    file.close()

with open("server/catalog/teste.mp3","wb+") as file:
    file.write(iv)
    file.close()

with open("server/catalog/898a08080d1840793122b7e118b27a95d117ebce.mp3","rb") as f1:
    while True:
        data = f1.read(16)

        if data==b'':
            exit(0)

        if len(data)!=16:
            tam = len(data)
            pad = 16-tam
            while len(data)!=16:
                data+=pad.to_bytes(1,byteorder='big')

        cipher = Cipher(algorithms.AES(pk), modes.OFB(iv))
        encryptor = cipher.encryptor()

        ct = encryptor.update(data) + encryptor.finalize()

        with open("server/catalog/teste.mp3","ab+") as f2:
            f2.write(ct)
            f2.close()
f1.close()

