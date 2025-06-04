import os
import json
import hashlib
from core.crypto_utils import decrypt_chunk, rsa_decrypt

PEER_DIR = "peers"
MANIFEST_DIR = "manifests"
DHT_PATH = "dht.json"

def get_file(manifest_hash, private_key, output_path):
    manifest_file = os.path.join(MANIFEST_DIR, f"{manifest_hash}.json")
    if not os.path.exists(manifest_file):
        raise FileNotFoundError("Manifest file not found.")

    with open(manifest_file, 'r') as m:
        manifest = json.load(m)

    iv = bytes.fromhex(manifest["iv"])
    aes_key = rsa_decrypt(private_key, bytes.fromhex(manifest["aes_key"]))

    if not os.path.exists(DHT_PATH):
        raise FileNotFoundError("DHT file missing.")

    with open(DHT_PATH, 'r') as f:
        dht = json.load(f)

    with open(output_path, 'wb') as out_file:
        for chunk_hash in manifest["chunks"]:
            peer = dht.get(chunk_hash)
            if not peer:
                raise ValueError(f"Chunk {chunk_hash} not found in DHT.")

            chunk_path = os.path.join(PEER_DIR, peer, chunk_hash)
            if not os.path.exists(chunk_path):
                raise FileNotFoundError(f"Chunk file {chunk_path} missing.")

            with open(chunk_path, 'rb') as c:
                encrypted_chunk = c.read()
                if hashlib.sha256(encrypted_chunk).hexdigest() != chunk_hash:
                    raise ValueError(f"Integrity check failed for chunk {chunk_hash}.")

                decrypted = decrypt_chunk(encrypted_chunk, aes_key, iv)
                out_file.write(decrypted)

    print(f"✅ File successfully recovered: {output_path}")
