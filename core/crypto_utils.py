from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# AES Key generation
def generate_aes_key():
    return os.urandom(32)  # 256-bit AES key

def generate_iv():
    return os.urandom(16)  # 128-bit IV

# Encrypt a chunk with AES
def encrypt_chunk(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

# Decrypt a chunk with AES
def decrypt_chunk(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()

# Encrypt AES key with RSA
def rsa_encrypt(public_key, data):
    return public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Decrypt AES key with RSA
def rsa_decrypt(private_key, data):
    return private_key.decrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# RSA Key Loading
def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())
