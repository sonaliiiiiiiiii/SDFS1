import os, json, gzip, hashlib, random
from core.crypto_utils import generate_aes_key, rsa_encrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

CHUNK_SIZE = 1024 * 1024
PEERS = ['peer1', 'peer2', 'peer3']
os.makedirs('manifests', exist_ok=True)
for p in PEERS:
    os.makedirs(os.path.join('peers', p), exist_ok=True)

def update_dht(chunk_hash, peer):
    dht = json.load(open('dht.json')) if os.path.exists('dht.json') else {}
    dht.setdefault(chunk_hash, []).append(peer)
    json.dump(dht, open('dht.json', 'w'), indent=4)

def add_file(path, public_key):
    aes_key, iv = generate_aes_key()

    # Compress file to .gz
    gz_path = path + '.gz'
    with open(path, 'rb') as f_in, gzip.open(gz_path, 'wb') as f_out:
        f_out.write(f_in.read())

    manifest = {
        'filename': os.path.basename(path),
        'chunks': [],
        'iv': iv.hex()
    }

    with open(gz_path, 'rb') as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break

            # Encrypt with PKCS7 padding
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            padder = sym_padding.PKCS7(128).padder()
            padded = padder.update(chunk) + padder.finalize()
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(padded) + encryptor.finalize()

            chunk_hash = hashlib.sha256(encrypted).hexdigest()
            for peer in random.sample(PEERS, 2):
                with open(os.path.join('peers', peer, chunk_hash), 'wb') as peer_file:
                    peer_file.write(encrypted)
            update_dht(chunk_hash, peer)
            manifest['chunks'].append(chunk_hash)

    encrypted_key = rsa_encrypt(public_key, aes_key)
    manifest['aes_key'] = encrypted_key.hex()

    manifest_hash = hashlib.sha256(json.dumps(manifest).encode()).hexdigest()
    with open(f"manifests/{manifest_hash}.json", 'w') as m:
        json.dump(manifest, m, indent=4)

    return manifest_hash
