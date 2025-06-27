import os, json, hashlib, gzip, shutil
from core.crypto_utils import rsa_decrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

def get_file(manifest_hash, private_key, output_path):
    manifest = json.load(open(f"manifests/{manifest_hash}.json"))
    aes_key = rsa_decrypt(private_key, bytes.fromhex(manifest['aes_key']))
    iv = bytes.fromhex(manifest['iv'])
    dht = json.load(open('dht.json'))

    decrypted_chunks = []

    for chunk_hash in manifest['chunks']:
        peers = dht.get(chunk_hash)
        if not peers:
            raise FileNotFoundError(f"Chunk {chunk_hash} not found in DHT.")
        
        chunk_path = os.path.join('peers', peers[0], chunk_hash)
        if not os.path.exists(chunk_path):
            raise FileNotFoundError(f"Chunk file {chunk_path} missing.")

        with open(chunk_path, 'rb') as f:
            encrypted = f.read()
            if hashlib.sha256(encrypted).hexdigest() != chunk_hash:
                raise ValueError(f"Chunk {chunk_hash} integrity check failed.")

            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded = decryptor.update(encrypted) + decryptor.finalize()

            # Unpad PKCS7
            unpadder = sym_padding.PKCS7(128).unpadder()
            decrypted = unpadder.update(padded) + unpadder.finalize()

            decrypted_chunks.append(decrypted)

    # Save reassembled gzipped file
    gz_path = output_path + '.gz'
    with open(gz_path, 'wb') as f:
        f.write(b''.join(decrypted_chunks))

    # Decompress
    with gzip.open(gz_path, 'rb') as gzfile:
        with open(output_path, 'wb') as out:
            shutil.copyfileobj(gzfile, out)
