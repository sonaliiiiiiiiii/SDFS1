import os
import json
import hashlib
import random
from core.crypto_utils import encrypt_chunk, generate_aes_key, rsa_encrypt

CHUNK_SIZE = 1024 * 1024
PEER_DIR = "peers"
MANIFEST_DIR = "manifests"
DHT_PATH = "dht.json"

os.makedirs(MANIFEST_DIR, exist_ok=True)
os.makedirs(PEER_DIR, exist_ok=True)
for i in range(1, 4):
    os.makedirs(os.path.join(PEER_DIR, f"peer{i}"), exist_ok=True)

def choose_peer():
    return f"peer{random.randint(1, 3)}"

def update_dht(chunk_hash, peer):
    dht = {}
    if os.path.exists(DHT_PATH):
        with open(DHT_PATH, 'r') as f:
            try:
                dht = json.load(f)
            except:
                pass
    dht[chunk_hash] = peer
    with open(DHT_PATH, 'w') as f:
        json.dump(dht, f, indent=2)

def add_file(file_path, public_key):
    aes_key = generate_aes_key()
    iv = os.urandom(16)

    manifest = {
        "filename": os.path.basename(file_path),  # <-- this line is key
        "chunks": [],
        "iv": iv.hex()
    }


    with open(file_path, 'rb') as f:
        while chunk := f.read(CHUNK_SIZE):
            encrypted_chunk = encrypt_chunk(chunk, aes_key, iv)
            chunk_hash = hashlib.sha256(encrypted_chunk).hexdigest()
            peer = choose_peer()
            chunk_path = os.path.join(PEER_DIR, peer, chunk_hash)
            with open(chunk_path, 'wb') as c:
                c.write(encrypted_chunk)
            update_dht(chunk_hash, peer)
            manifest["chunks"].append(chunk_hash)

    encrypted_key = rsa_encrypt(public_key, aes_key)
    manifest["aes_key"] = encrypted_key.hex()

    manifest_hash = hashlib.sha256(json.dumps(manifest).encode()).hexdigest()
    with open(os.path.join(MANIFEST_DIR, f"{manifest_hash}.json"), 'w') as m:
        json.dump(manifest, m)

    return manifest_hash
