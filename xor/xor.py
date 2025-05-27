# MIT License
# Copyright (c) 2025 0xsweat
# See LICENSE file for full license text.
"""
Author : 0xsweat
Date : 2025/05/24

This file is for encrypting and decrypting data with XOR,
The purpose is to simplify using xor for encryption/decryption.
"""
import argparse
import random
from getpass import getpass

def keygen(output="key.txt", keysize=4096) -> bytes:
    """
    This function generates a random key of specified size and writes it to a file.
    
    Args :  
        output : The name of the output file where the key will be saved.
        keysize : The size of the key to be generated in bytes, default is 4096.
    Returns :  bytes
    """
    key: str = ""
    for _ in range(keysize):
        key += chr(random.randrange(0,255))
    with open(output, "wb") as f:
        f.write(bytes(key, encoding="UTF-8"))
    return bytes(key, encoding="UTF-8")

def xor(data: str | bytes, key: str | bytes, output="", data_from_file=False, key_from_file=False) -> bytes:
    """
    This function performs XOR encryption/decryption on the given data using the provided key.

    Args :
        data : The data to be encrypted or decrypted, can be a string or a file path.
        key : The key to be used for encryption/decryption, can be a string or a file path.
        output : The name of the output file where the result will be saved, if not provided, it will return the result as bytes.
        data_from_file : If True, reads data from the specified file, otherwise treats data as a string.
        key_from_file : If True, reads the key from the specified file, otherwise treats key as a string.
    Returns : bytes
    """
    string: str = ""
    if data_from_file:
        with open(data, "rb") as f:
            contents: str = f.read().decode()
    else:
        contents: str = data if type(data) == str else data.decode()
    if key_from_file:
        with open(key, "rb") as f:
            key: str = f.read().decode()
    else:
        key: str = key if type(key) == str else key.decode()
    key_pointer: int = 0
    for char in contents:
        string += chr(ord(char) ^ ord(key[key_pointer]))
        key_pointer += 1 if key_pointer < len(key) else -key_pointer
    if output:
        with open(output, "wb") as f:
            f.write(bytes(string, encoding="UTF-8"))
    return bytes(string, encoding="UTF-8")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""
        This program is for encrypting/decrypting data using XOR, it also generates keys for it.
        """,
        epilog="Author : 0xsweat 2025/05/24"
        )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-f", "--file", help="The file to encrypt or decrypt.", type=str)
    parser.add_argument("-o", "--output", help="The output file.", type=str)
    group.add_argument("-g", "--generate", help="Tells the program to generate a key.", action='store_true')
    parser.add_argument("-ks", "--keysize", help="Size of the key, default is 4096 bytes.")
    parser.add_argument("-k", "--key", help="The key to be used for encryption/decryption")
    args = parser.parse_args()
    if args.generate:
        ks: int = 4096
        out: str = "key.txt"
        if args.keysize:
            ks = args.keysize
        if args.output:
            out = args.output
        keygen(out, ks)
        print(f"key generation finished. Key written to : {out}")
    else:
        string: str = args.file
        string_file: bool = True
        key_file: bool = True
        out: str = args.output
        k: str = args.key
        if not args.file:
            string = getpass("Text -> ")
            string_file = False
        if not args.key:
            k = getpass("Key -> ")
            key_file = False
        if not args.output:
            out = input("Output file -> ")
        xor(string, k, out, string_file, key_file)