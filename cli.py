# 📁 File: cli.py
import argparse
from core.uploader import add_file
from core.retriever import get_file
from core.crypto_utils import generate_keys

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SDFS CLI - Secure Decentralized File System")
    subparsers = parser.add_subparsers(dest="command")

    # sdfs add <file>
    add_parser = subparsers.add_parser("add", help="Add a file to SDFS")
    add_parser.add_argument("file", help="Path to file to upload")

    # sdfs get <manifest_hash>
    get_parser = subparsers.add_parser("get", help="Retrieve a file from SDFS")
    get_parser.add_argument("manifest", help="Manifest hash")
    get_parser.add_argument("out", help="Path to save reconstructed file")

    args = parser.parse_args()

    private_key, public_key = generate_keys()

    if args.command == "add":
        manifest_hash = add_file(args.file, public_key)
        print(f"Manifest hash: {manifest_hash}")

    elif args.command == "get":
        get_file(args.manifest, private_key, args.out)

    else:
        parser.print_help()
