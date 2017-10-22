import os
import struct
import sys

from datetime import datetime
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.PublicKey import RSA

chunksize = 1024 * 64
enc_dir = 'enc/'
dec_dir = 'dec/'
key_dir = 'keys/'
in_dir = 'in/'

KEY_LENGTH = 1024

file_key_length = 128


def pad16(data):
    if (len(data) % 16 == 0):
        return data
    return data + b'=' * (16 - len(data) % 16)


def genKeys():
    if (os.path.exists(key_dir) == 0):
        os.makedirs(key_dir)
    random_gen = Random.new().read
    private_key = RSA.generate(KEY_LENGTH, random_gen)

    file = open(key_dir + 'key', 'wb')
    file.write(private_key.exportKey())
    file = open(key_dir + 'key.pub', 'wb')
    file.write(private_key.publickey().exportKey())  # genKeys()


def enc_RSA(message, public_key):
    file = open(public_key)
    pub_key = file.read()
    key = RSA.importKey(pub_key)
    return key.encrypt(message, 32)


def dec_RSA(encrypted):
    file = open('keys/key')
    pub_key = file.read()
    key = RSA.importKey(pub_key)
    return key.decrypt(encrypted)


def encrypt(file_name, public_key):
    if (os.path.exists(enc_dir) == 0):
        os.makedirs(enc_dir)
    time = datetime.now()
    key = Random.new().read(16)
    iv = Random.new().read(AES.block_size)

    cipher = AES.new(key, AES.MODE_CBC, iv)

    infile = open(in_dir + file_name, 'rb')
    filesize = os.path.getsize(in_dir + file_name)

    outfile = open(enc_dir + file_name, 'wb')

    encrypted_key = enc_RSA(key, public_key)
    outfile.write(struct.pack('<Q', filesize))
    outfile.write(iv)
    outfile.write(encrypted_key[0])

    print('encrypting', end="")
    while True:
        print('.', end="")
        chunk = infile.read(chunksize)
        if (len(chunk) == 0):
            break
        chunk = pad16(chunk)
        outfile.write(cipher.encrypt(chunk))
    print()
    print('Finished, took: ', end='')
    print(datetime.now() - time, end="\n")


def decrypt(file_name):
    if (os.path.exists(dec_dir) == 0):
        os.makedirs(dec_dir)

    time = datetime.now()

    infile = open(enc_dir + file_name, 'rb')
    rawfilesize = infile.read(struct.calcsize('Q'))
    filesize = struct.unpack('<Q', rawfilesize)[0]
    iv = infile.read(AES.block_size)
    key = infile.read(file_key_length)
    key = dec_RSA(key)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    outfile = open(dec_dir + file_name, 'wb')
    print('decrypting', end="")
    while True:
        print('.', end="")
        chunk = infile.read(chunksize)
        if len(chunk) == 0:
            break
        outfile.write(cipher.decrypt(chunk))

    outfile.truncate(filesize)
    print()
    print('Finished, took: ' ,end='')
    print(datetime.now() - time,end="\n")


def main():
    if len(sys.argv) > 1:
        if sys.argv[1] == "G":
            genKeys()
            print("Keys has been generated")
        elif sys.argv[1] == "E":
            encrypt(sys.argv[2], sys.argv[3])
        elif sys.argv[1] == "D":
            decrypt(sys.argv[2])
        else:
            print("Invalid argument")

    else:
        print("Invalid argument")


if __name__ == "__main__":
    main()
