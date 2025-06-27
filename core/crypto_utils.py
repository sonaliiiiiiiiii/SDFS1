import os
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def generate_keys():
    if os.path.exists("private.pem") and os.path.exists("public.pem"):
        private_key = serialization.load_pem_private_key(open("private.pem","rb").read(), password=None, backend=default_backend())
        public_key = serialization.load_pem_public_key(open("public.pem","rb").read(), backend=default_backend())
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key()
        with open("private.pem","wb") as pf:
            pf.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
        with open("public.pem","wb") as pf:
            pf.write(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
    return private_key, public_key

def generate_aes_key():
    return os.urandom(32), os.urandom(16)

def encrypt_chunk(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    padder = sym_padding.PKCS7(128).padder()
    return cipher.encryptor().update(padder.update(data) + padder.finalize()) + cipher.encryptor().finalize()

def decrypt_chunk(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decrypted = cipher.decryptor().update(data) + cipher.decryptor().finalize()
    return sym_padding.PKCS7(128).unpadder().update(decrypted) + sym_padding.PKCS7(128).unpadder().finalize()

def rsa_encrypt(public_key, data):
    return public_key.encrypt(data, asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def rsa_decrypt(private_key, data):
    return private_key.decrypt(data, asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def load_private_key(path):
    return serialization.load_pem_private_key(open(path,"rb").read(), password=None, backend=default_backend())

def load_public_key(path):
    return serialization.load_pem_public_key(open(path,"rb").read(), backend=default_backend())
